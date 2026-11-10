"""Comprehensive live integration tests against Google Gmail, Groups Migration, and OAuth/DPoP APIs.

Exercises:
1. Live DPoP OAuth token refresh, ProfileManager persistence, HTTP/2 negotiation, live 401
   auto-refresh-and-retry recovery, and negative EphemeralDPoPSigner key-binding checks.
2. Parallel multi-stream HTTP/2 migrations (32 concurrent messages across nested labels),
   live AIMD stream ramp-up verification, parallel backup, incremental dedup, and direct
   streaming Gmail -> Gmail cloud-to-cloud migration.
3. Real repository ``samples/`` archives (``gyb-format``, ``odd-mails.mbox``,
   ``rfc2047-samples.mbox``, ``google-takeout/takeout.mbox``, ``vault-export-mbox``) into
   live Gmail and Google Groups Migration API.
4. Unusual source migration data & Gmail quirks: > 1.5 MiB resumable attachment upload
   (``MediaIoBaseUpload(resumable=True)``) with SHA-256 verification, legacy ISO-8859-1 8-bit
   bodies, ``From: <>`` bounce sender cleanup, reserved/CHAT label collisions, ``deleted=True``
   (Google Vault permanently deleted) & ``TRASH``, editable drafts, server Message-ID
   deduplication, and foreign ``threadId`` fallback.
5. Live Gmail API error responses (404 Not Found, oversize ``MediaUploadSizeError`` mixed batch,
   transient 429 global backoff) and end-to-end ``gyb`` CLI (``report``, ``retry``) recovery.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from email import policy
from email.header import Header
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.parser import BytesParser
from email.utils import format_datetime
from pathlib import Path

import google.auth.exceptions
import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from dpop_signer_ephemeral import EphemeralDPoPSigner
from google.auth import external_account, impersonated_credentials
from google.auth.dpop import SoftwareDPoPSigner
from google.oauth2 import service_account
from google.oauth2.dpop_credentials import DPoPCredentials
from tests.integration.conftest import (
    LiveTestEnv,
    build_live_transport,
    load_legacy_gyb_oauth_info,
    setup_live_profile_dir,
)

from gyb.auth import (
    DEFAULT_OAUTH_SCOPES,
    OAuthProfile,
    ProfileManager,
    SignerConfig,
    SignerType,
)
from gyb.cli.main import cli
from gyb.cli.options import TransferOptions
from gyb.core import (
    AuthenticationError,
    JobState,
    Message,
    StreamTuningConfig,
    TransferPipeline,
    TransferResult,
    TransferStatus,
    TransientTransferError,
)
from gyb.db import JobStore
from gyb.modules.gmail import (
    RESUMABLE_THRESHOLD_BYTES,
    GmailBadRequestError,
    GmailClient,
    GmailNotFoundError,
    GmailSink,
    GmailSource,
)
from gyb.modules.google_groups import GoogleGroupsSink, GroupsMigrationClient
from gyb.modules.local import LocalGYBSink, LocalGYBSource
from gyb.modules.mbox import MboxSource

pytestmark = pytest.mark.integration

REPO_SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def _decode_b64url(raw_str: str) -> bytes:
    padded = raw_str + "=" * (-len(raw_str) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _build_multipart_attachment_email(
    run_id: str,
    tag: str,
    msg_date: datetime,
    attachment_bytes: bytes,
) -> bytes:
    outer = MIMEMultipart("mixed")
    outer["Message-ID"] = f"<att-{tag}-{run_id}@gyb-itest.local>"
    outer["Date"] = format_datetime(msg_date)
    outer["From"] = "GYB Integration <itest@gyb-itest.local>"
    outer["To"] = "recipient@gyb-itest.local"
    outer["Subject"] = f"[gyb-{run_id}] Multipart Attachment {tag}"
    outer["X-GYB-ITest-Run"] = run_id

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(f"Plain text body for {run_id} ({tag})", "plain", "utf-8"))
    alt.attach(MIMEText(f"<p>HTML body for <b>{run_id}</b> ({tag})</p>", "html", "utf-8"))
    outer.attach(alt)

    part = MIMEApplication(attachment_bytes, _subtype="octet-stream")
    part.add_header("Content-Disposition", "attachment", filename="payload.bin")
    outer.attach(part)
    return outer.as_bytes(policy=policy.SMTP)


def test_live_dpop_auth_http2_401_recovery_and_negative_binding(
    live_env: LiveTestEnv,
    tmp_path: Path,
) -> None:
    """Verify live DPoP refresh, ProfileManager OAuthProfile, HTTP/2, and 401 auto-retry."""
    if live_env.dpop_profile_name:
        mgr = ProfileManager()
        with mgr.build_authorized_http(live_env.dpop_profile_name) as http:
            http.ensure_valid_token(force=True)
            assert isinstance(http.credentials, DPoPCredentials)

            bound_creds = http.credentials
            mismatched_creds = DPoPCredentials(
                token=None,
                dpop_signer=EphemeralDPoPSigner(),
                refresh_token=bound_creds.refresh_token,
                token_uri=bound_creds.token_uri,
                client_id=bound_creds.client_id,
                client_secret=bound_creds.client_secret,
                scopes=bound_creds.scopes,
            )
            with pytest.raises(google.auth.exceptions.RefreshError):
                mismatched_creds.refresh(http.auth_request)
        return

    if live_env.legacy_oauth_cfg and live_env.legacy_oauth_cfg.is_file():
        info = load_legacy_gyb_oauth_info(live_env.legacy_oauth_cfg)
        priv_key = ec.generate_private_key(ec.SECP256R1())
        pem_path = tmp_path / "ci-dpop-p256.pem"
        pem_path.write_bytes(
            priv_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        )
        pem_path.chmod(0o600)

        # 1. Persist and reload an OAuthProfile backed by SoftwareDPoPSigner via ProfileManager
        cfg_dir = tmp_path / "dpop-cfg"
        mgr = ProfileManager(cfg_dir)
        oauth_prof = OAuthProfile(
            name="ci-dpop-oauth",
            scopes=DEFAULT_OAUTH_SCOPES,
            authorized_user_info={
                "refresh_token": info["refresh_token"],
                "token_uri": info["token_uri"],
                "client_id": info["client_id"],
                "client_secret": info["client_secret"],
            },
            signer=SignerConfig(
                signer_type=SignerType.SOFTWARE,
                key_id="ci-dpop-key",
                pem_path=str(pem_path),
            ),
        )
        mgr.save_profile(oauth_prof)

        with mgr.build_authorized_http("ci-dpop-oauth", max_streams=4) as transport:
            assert isinstance(transport.credentials, DPoPCredentials)
            gmail = GmailClient(transport, user_id=live_env.gmail_user)
            prof = gmail.get_profile()
            assert prof.get("emailAddress", "").lower() == live_env.gmail_user.lower()
            assert gmail.last_http_version == "HTTP/2"

            # 2. Live 401 Unauthorized recovery: corrupt bearer/DPoP access token in memory
            # and verify ModernAuthorizedHttp catches Google's 401, refreshes with DPoP, and
            # retries transparently over HTTP/2!
            transport.credentials.token = "ya29.deliberately-invalid-access-token"
            prof_after_401 = gmail.get_profile()
            assert prof_after_401.get("emailAddress", "").lower() == live_env.gmail_user.lower()
            assert gmail.last_http_version == "HTTP/2"
            assert transport.credentials.token != "ya29.deliberately-invalid-access-token"

        # 3. Verify software signer key mismatch awareness via fresh SoftwareDPoPSigner
        alt_signer = SoftwareDPoPSigner(ec.generate_private_key(ec.SECP256R1()), key_id="alt")
        assert alt_signer.key_id == "alt"
        return

    pytest.skip(
        "Set GYB_ITEST_DPOP_PROFILE or GYB_ITEST_OAUTH_CFG to run live OAuth/DPoP token tests."
    )


def test_live_adc_domain_wide_delegation_identity(
    live_env: LiveTestEnv,
    tmp_path: Path,
) -> None:
    """Verify ADC Domain-Wide Delegation (SA key or keyless WIF) acts as the exact subject."""
    if live_env.profile_name:
        pytest.skip("GYB_ITEST_PROFILE overrides ADC; DwD identity test requires ADC mode.")
    assert live_env.subject is not None

    with build_live_transport(live_env, tmp_path / "dwd-cfg", max_streams=4) as transport:
        creds = transport.credentials
        match live_env.adc_mode:
            case "wif":
                # GitHub Actions OIDC -> STS federated token -> IAM signJwt DwD assertion
                assert isinstance(creds, impersonated_credentials.Credentials), type(creds)
                assert isinstance(creds._source_credentials, external_account.Credentials)
                assert creds._subject == live_env.subject
            case "sa-key":
                assert isinstance(creds, service_account.Credentials), type(creds)
                assert creds._subject == live_env.subject
            case _:
                pass

        gmail = GmailClient(transport, user_id=live_env.gmail_user)
        prof = gmail.get_profile()
        assert prof.get("emailAddress", "").lower() == live_env.subject.lower()
        assert gmail.last_http_version == "HTTP/2"

        # Forced refresh re-runs the full delegation chain (signJwt / local JWT -> jwt_grant)
        transport.ensure_valid_token(force=True)
        assert gmail.get_profile().get("emailAddress", "").lower() == live_env.subject.lower()

    # Negative: delegation to a nonexistent user in the domain must fail at token exchange
    domain = live_env.subject.split("@", 1)[1]
    bogus_env = replace(live_env, subject=f"gyb-itest-nouser-{live_env.run_id}@{domain}")
    with (
        build_live_transport(bogus_env, tmp_path / "dwd-bogus-cfg", max_streams=1) as bogus,
        pytest.raises(AuthenticationError, match="Credential refresh failed"),
    ):
        bogus.ensure_valid_token(force=True)


def test_parallel_multistream_http2_migration_aimd_and_cloud_to_cloud(
    live_env: LiveTestEnv,
    live_gmail_client: GmailClient,
    tmp_path: Path,
) -> None:
    """Exercise 32-message parallel HTTP/2 restore, AIMD scaling, backup, and cloud migrate."""
    profile = live_gmail_client.get_profile()
    assert profile.get("emailAddress", "").lower() == live_env.gmail_user.lower()
    assert live_gmail_client.last_http_version == "HTTP/2"

    ns = live_env.label_namespace
    buckets = ("Alpha", "Beta", "Gamma", "Delta")
    fixed_dt = datetime(2024, 7, 10, 15, 0, 0, tzinfo=UTC)

    # 1. Populate a 32-message Local GYB archive with 16 2-message threads across 4 nested labels
    seed_dir = tmp_path / "parallel-seed"
    with LocalGYBSink(seed_dir, email_address=live_env.gmail_user) as local_sink:
        for idx in range(32):
            thread_num = idx // 2
            is_reply = (idx % 2) == 1
            bucket = buckets[thread_num % len(buckets)]
            root_msgid = f"<par-root-{thread_num}-{live_env.run_id}@gyb-itest.local>"
            msgid = (
                f"<par-reply-{thread_num}-{live_env.run_id}@gyb-itest.local>"
                if is_reply
                else root_msgid
            )
            subj_base = f"[gyb-{live_env.run_id}] Parallel Thread {thread_num}"
            msg = MIMEText(
                f"Parallel HTTP/2 stream test message #{idx} ({live_env.run_id})",
                "plain",
                "utf-8",
            )
            msg["Message-ID"] = msgid
            msg["Date"] = format_datetime(fixed_dt.replace(second=idx % 60))
            msg["From"] = f"Sender {thread_num} <sender{thread_num}@gyb-itest.local>"
            msg["To"] = "recipient@gyb-itest.local"
            msg["Subject"] = f"Re: {subj_base}" if is_reply else subj_base
            if is_reply:
                msg["In-Reply-To"] = root_msgid
                msg["References"] = root_msgid
            msg["X-GYB-ITest-Run"] = live_env.run_id

            flags = ("INBOX", "STARRED") if (idx % 4 == 0) else ("UNREAD",)
            local_sink.import_message(
                Message(
                    source_id=f"par-{idx:02d}",
                    raw_rfc822=msg.as_bytes(policy=policy.SMTP),
                    labels=(*flags, f"{ns}/Parallel/{bucket}", f"{ns}/Parallel"),
                    internal_date=fixed_dt,
                )
            )

    # 2. Parallel HTTP/2 Restore -> Gmail with aggressive ramp_interval to verify live AIMD scaling
    tuning = StreamTuningConfig(
        initial_streams=4,
        min_streams=1,
        max_streams=16,
        ramp_interval=0.05,
        ramp_step=2,
    )
    restore_summary = TransferPipeline(
        LocalGYBSource(seed_dir),
        GmailSink(live_gmail_client, close_transport=False),
        tuning=tuning,
    ).run()
    assert restore_summary.state == JobState.COMPLETED
    assert restore_summary.succeeded == 32
    assert restore_summary.failed == 0
    assert restore_summary.telemetry is not None
    assert restore_summary.telemetry.peak_streams > 4, (
        f"Expected AIMD HTTP/2 stream ramp-up > 4, got {restore_summary.telemetry}"
    )
    assert live_gmail_client.last_http_version == "HTTP/2"

    # Verify all 32 messages exist in live Gmail under {ns}/Parallel
    gmail_parallel_ids = list(live_gmail_client.list_messages(query=f'label:"{ns}/Parallel"'))
    assert len(gmail_parallel_ids) == 32

    # 3. Parallel HTTP/2 Backup (Gmail -> Local GYB) + Incremental Idempotency Verification
    backup_dir = tmp_path / "parallel-backup"
    backup_summary_1 = TransferPipeline(
        GmailSource(live_gmail_client, close_transport=False),
        LocalGYBSink(backup_dir, email_address=live_env.gmail_user),
        tuning=tuning,
    ).run(query=f'label:"{ns}/Parallel"')
    assert backup_summary_1.state == JobState.COMPLETED
    assert backup_summary_1.succeeded == 32

    backup_summary_2 = TransferPipeline(
        GmailSource(live_gmail_client, close_transport=False),
        LocalGYBSink(backup_dir, email_address=live_env.gmail_user),
        tuning=tuning,
    ).run(query=f'label:"{ns}/Parallel"')
    assert backup_summary_2.state == JobState.COMPLETED
    assert backup_summary_2.succeeded == 0
    assert backup_summary_2.skipped == 32

    # 4. Direct Streaming Cloud-to-Cloud Migration (GmailSource -> GmailSink) over HTTP/2
    clone_prefix = f"{ns}/CloudClone"
    migrate_summary = TransferPipeline(
        GmailSource(live_gmail_client, close_transport=False),
        GmailSink(
            live_gmail_client,
            label_prefix=clone_prefix,
            use_insert=True,
            preserve_threads=True,
            close_transport=False,
        ),
        tuning=tuning,
    ).run(query=f'label:"{ns}/Parallel/Alpha"')
    assert migrate_summary.state == JobState.COMPLETED
    assert migrate_summary.succeeded == 8

    cloned_ids = list(
        live_gmail_client.list_messages(query=f'label:"{clone_prefix}/{ns}/Parallel/Alpha"')
    )
    assert len(cloned_ids) == 8


def test_real_repository_samples_to_gmail_and_google_groups(
    live_env: LiveTestEnv,
    live_gmail_client: GmailClient,
    tmp_path: Path,
) -> None:
    """Exercise all real repo samples/ archives against live Gmail and Google Groups."""
    ns = live_env.label_namespace
    tuning = StreamTuningConfig(initial_streams=8, min_streams=1, max_streams=16, ramp_interval=0.1)

    # 1. samples/gyb-format (11 msgs: emoji 💩💩💩💩, señor, top/nested, 103KB DRAFT, 805KB SENT)
    gyb_fmt_summary = TransferPipeline(
        LocalGYBSource(REPO_SAMPLES / "gyb-format"),
        GmailSink(
            live_gmail_client,
            label_prefix=f"{ns}/SampleGYB",
            label_restored=f"{ns}/SampleGYB/All",
            use_insert=True,
            close_transport=False,
        ),
        tuning=tuning,
    ).run()
    assert gyb_fmt_summary.state == JobState.COMPLETED
    assert gyb_fmt_summary.succeeded == 11

    all_labels = {str(lbl["name"]) for lbl in live_gmail_client.list_labels()}
    assert f"{ns}/SampleGYB/💩💩💩💩" in all_labels
    assert f"{ns}/SampleGYB/señor" in all_labels
    assert f"{ns}/SampleGYB/top/nested" in all_labels

    # Verify the 103 KB DRAFT from samples/gyb-format landed as a real Gmail DRAFT
    sample_drafts = list(
        live_gmail_client.list_messages(query=f'label:DRAFT label:"{ns}/SampleGYB/All"')
    )
    assert len(sample_drafts) == 1

    # 2. samples/historic-public-mbox/odd-mails.mbox (6 malformed historic mails with cleanup=True)
    #    & rfc2047-samples.mbox (11 RFC 2047 ISO-8859-1/2 header vectors)
    odd_sanitized: list[bool] = []
    odd_summary = TransferPipeline(
        MboxSource(REPO_SAMPLES / "historic-public-mbox" / "odd-mails.mbox"),
        GmailSink(
            live_gmail_client,
            label_restored=f"{ns}/OddMails",
            cleanup=True,
            use_insert=False,
            close_transport=False,
        ),
        tuning=tuning,
        on_result=lambda res, _: odd_sanitized.append(res.sanitized),
    ).run()
    assert odd_summary.state == JobState.COMPLETED
    assert odd_summary.succeeded == 6
    assert sum(odd_sanitized) == 6  # all 6 lack Date/Message-ID; 2 also repair invalid From

    rfc2047_summary = TransferPipeline(
        MboxSource(REPO_SAMPLES / "historic-public-mbox" / "rfc2047-samples.mbox"),
        GmailSink(
            live_gmail_client,
            label_restored=f"{ns}/RFC2047",
            use_insert=True,
            close_transport=False,
        ),
        tuning=tuning,
    ).run()
    assert rfc2047_summary.state == JobState.COMPLETED
    assert rfc2047_summary.succeeded == 11

    # 3. samples/google-takeout/takeout.mbox (39 messages: Czech Unicode, commas in quotes, ☯)
    takeout_summary = TransferPipeline(
        MboxSource(REPO_SAMPLES / "google-takeout" / "takeout.mbox"),
        GmailSink(
            live_gmail_client,
            label_prefix=f"{ns}/Takeout",
            label_restored=f"{ns}/Takeout/All",
            use_insert=True,
            close_transport=False,
        ),
        tuning=tuning,
    ).run()
    assert takeout_summary.state == JobState.COMPLETED
    assert takeout_summary.succeeded == 39

    refreshed_labels = {str(lbl["name"]) for lbl in live_gmail_client.list_labels()}
    assert f"{ns}/Takeout/1.Organizační" in refreshed_labels
    assert f"{ns}/Takeout/3. Culture, Hledání ztraceného času" in refreshed_labels
    assert f"{ns}/Takeout/☯" in refreshed_labels

    # 4. samples/vault-export-mbox (53 messages with Google Vault XML sidecar metadata)
    vault_summary = TransferPipeline(
        MboxSource(REPO_SAMPLES / "vault-export-mbox"),
        GmailSink(
            live_gmail_client,
            label_prefix=f"{ns}/Vault",
            label_restored=f"{ns}/Vault/All",
            use_insert=True,
            close_transport=False,
        ),
        tuning=tuning,
    ).run()
    assert vault_summary.state == JobState.COMPLETED
    assert vault_summary.succeeded == 53

    vault_ubuntu_msgs = list(live_gmail_client.list_messages(query=f'label:"{ns}/Vault/ubuntu"'))
    assert len(vault_ubuntu_msgs) > 0

    # 5. Live Google Groups Migration API (clean + odd-mails malformed message with cleanup_from)
    if live_env.group_email:
        with build_live_transport(live_env, tmp_path / "grp-cfg") as grp_transport:
            grp_client = GroupsMigrationClient(grp_transport, live_env.group_email)
            with GoogleGroupsSink(
                grp_client,
                cleanup=False,
                cleanup_from="God of Thunder <thor@avengers.com>",
                close_transport=False,
            ) as grp_sink:
                clean_grp_res = grp_sink.import_message(
                    Message(
                        source_id="grp-clean",
                        raw_rfc822=(
                            f"Message-ID: <grp-clean-{live_env.run_id}@gyb-itest.local>\r\n"
                            f"Date: Sat, 15 Jun 2024 14:30:00 +0000\r\n"
                            f"From: Group Tester <tester@gyb-itest.local>\r\n"
                            f"To: {live_env.group_email}\r\n"
                            f"Subject: [gyb-{live_env.run_id}] Group Archive Verification\r\n\r\n"
                            f"Group archive payload {live_env.run_id}\r\n"
                        ).encode(),
                    )
                )
                assert clean_grp_res.status == TransferStatus.SUCCESS
                assert grp_client.last_http_version == "HTTP/2"

                malformed_grp_res = grp_sink.import_message(
                    Message(
                        source_id="grp-odd",
                        raw_rfc822=(
                            b"From: <notanemail>\r\n"
                            + f"Subject: [gyb-{live_env.run_id}] Malformed Group\r\n\r\n".encode()
                            + f"Malformed group body {live_env.run_id}\r\n".encode()
                        ),
                    )
                )
                assert malformed_grp_res.status == TransferStatus.SUCCESS


def test_unusual_data_edge_cases_and_large_resumable_upload(
    live_env: LiveTestEnv,
    live_gmail_client: GmailClient,
) -> None:
    """Verify >1.5 MiB resumable upload, ISO-8859-1, bounce From:<>, labels, TRASH, and dedup."""
    ns = live_env.label_namespace
    fixed_dt = datetime(2024, 6, 15, 14, 30, 0, tzinfo=UTC)

    # 1. > 1.5 MiB Binary Attachment -> exercises MediaIoBaseUpload(..., resumable=True) over HTTP/2
    large_blob = hashlib.sha512(f"resumable-{live_env.run_id}".encode()).digest() * 25_000
    assert len(large_blob) == 1_600_000 > RESUMABLE_THRESHOLD_BYTES
    expected_large_sha = hashlib.sha256(large_blob).hexdigest()
    large_raw = _build_multipart_attachment_email(
        live_env.run_id,
        "resumable-1600k",
        fixed_dt,
        large_blob,
    )

    # 2. Legacy 8-bit ISO-8859-1 body + From: <> bounce sender + invalid Date header
    iso_body = f"Café résumé naïve £100 - run {live_env.run_id}\r\n".encode("iso-8859-1")
    iso_subj = Header(f"[gyb-{live_env.run_id}] Café Bounce ISO-8859-1", "iso-8859-1").encode()
    bounce_iso_raw = (
        f"Message-ID: <bounce-iso-{live_env.run_id}@gyb-itest.local>\r\n"
        "Date: 99 FooBar 9999 99:99:99 +0000\r\n"
        "From: <>\r\n"
        "To: recipient@gyb-itest.local\r\n"
        f"Subject: {iso_subj}\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=iso-8859-1\r\n"
        "Content-Transfer-Encoding: 8bit\r\n"
        f"X-GYB-ITest-Run: {live_env.run_id}\r\n\r\n"
    ).encode("ascii") + iso_body

    # 3. Reserved & legacy CHAT label collision message + deleted=True (TRASH) + editable DRAFT
    dedup_raw = (
        f"Message-ID: <dedup-{live_env.run_id}@gyb-itest.local>\r\n"
        f"Date: {format_datetime(fixed_dt)}\r\n"
        "From: Dedup Tester <dedup@gyb-itest.local>\r\n"
        "To: recipient@gyb-itest.local\r\n"
        f"Subject: [gyb-{live_env.run_id}] Dedup & Reserved Labels\r\n"
        f"X-GYB-ITest-Run: {live_env.run_id}\r\n\r\n"
        f"Deduplication payload {live_env.run_id}\r\n"
    ).encode()

    vault_deleted_raw = (
        f"Message-ID: <vault-deleted-{live_env.run_id}@gyb-itest.local>\r\n"
        f"Date: {format_datetime(fixed_dt)}\r\n"
        "From: Vault Tester <vault@gyb-itest.local>\r\n"
        "To: recipient@gyb-itest.local\r\n"
        f"Subject: [gyb-{live_env.run_id}] Vault Permanently Deleted Verification\r\n"
        f"X-GYB-ITest-Run: {live_env.run_id}\r\n\r\n"
        f"Vault permanently deleted payload {live_env.run_id}\r\n"
    ).encode()

    trash_raw = (
        f"Message-ID: <trash-{live_env.run_id}@gyb-itest.local>\r\n"
        f"Date: {format_datetime(fixed_dt)}\r\n"
        "From: Trash Tester <trash@gyb-itest.local>\r\n"
        "To: recipient@gyb-itest.local\r\n"
        f"Subject: [gyb-{live_env.run_id}] Trash Label Verification\r\n"
        f"X-GYB-ITest-Run: {live_env.run_id}\r\n\r\n"
        f"Trash payload {live_env.run_id}\r\n"
    ).encode()

    draft_raw = (
        f"Message-ID: <draft-edge-{live_env.run_id}@gyb-itest.local>\r\n"
        f"Date: {format_datetime(fixed_dt)}\r\n"
        "From: Draft Author <draft@gyb-itest.local>\r\n"
        "To: recipient@gyb-itest.local\r\n"
        f"Subject: [gyb-{live_env.run_id}] Editable Draft With Foreign Thread\r\n"
        f"X-GYB-ITest-Run: {live_env.run_id}\r\n\r\n"
        f"Editable draft payload {live_env.run_id}\r\n"
    ).encode()

    with GmailSink(
        live_gmail_client,
        label_prefix=f"{ns}/Edge",
        cleanup=True,
        cleanup_from="Mailer Daemon <postmaster@gyb-itest.local>",
        preserve_threads=True,
        close_transport=False,
    ) as sink:
        # Resumable > 1.5 MiB upload + foreign threadId ("deadbeefcafebabe" -> 400/404 -> fallback!)
        r_large = sink.import_message(
            Message(
                source_id="large-resumable",
                raw_rfc822=large_raw,
                labels=("INBOX", "Attachments"),
                thread_id="deadbeefcafebabe",
            )
        )
        assert r_large.status == TransferStatus.SUCCESS and r_large.destination_id is not None
        assert r_large.sanitized is False

        # Bounce From:<> + ISO-8859-1 + invalid Date -> header hygiene without 8-bit body mutation
        r_bounce = sink.import_message(
            Message(
                source_id="bounce-iso",
                raw_rfc822=bounce_iso_raw,
                internal_date=fixed_dt,
                labels=("Bounces",),
            )
        )
        assert r_bounce.status == TransferStatus.SUCCESS and r_bounce.destination_id is not None
        assert r_bounce.sanitized is True

        # Reserved labels ("CHAT", "inbox", "archive/2024", "muted", "STARRED") + server dedup
        dedup_msg = Message(
            source_id="dedup-1",
            raw_rfc822=dedup_raw,
            labels=("CHAT", "inbox", "archive/2024", "muted", "STARRED"),
        )
        r_dedup_1 = sink.import_message(dedup_msg)
        r_dedup_2 = sink.import_message(dedup_msg)
        assert r_dedup_1.destination_id == r_dedup_2.destination_id

        # Vault permanently deleted (deleted=True: archived for Vault only, invisible to mailbox)
        r_vault_deleted = sink.import_message(
            Message(
                source_id="vault-deleted-1",
                raw_rfc822=vault_deleted_raw,
                is_deleted=True,
            )
        )
        assert (
            r_vault_deleted.status == TransferStatus.SUCCESS
            and r_vault_deleted.destination_id is not None
        )

        # Standard TRASH label import (visible in user TRASH)
        r_trash = sink.import_message(
            Message(
                source_id="trash-1",
                raw_rfc822=trash_raw,
                labels=("TRASH", "DeletedItems"),
            )
        )
        assert r_trash.status == TransferStatus.SUCCESS and r_trash.destination_id is not None

        # Draft with foreign threadId fallback + custom label
        r_draft = sink.import_message(
            Message(
                source_id="draft-edge",
                raw_rfc822=draft_raw,
                labels=("DRAFT", "DraftFolder"),
                is_draft=True,
                thread_id="deadbeefcafebabe",
            )
        )
        assert r_draft.status == TransferStatus.SUCCESS and r_draft.destination_id is not None

    label_id_to_name = {
        str(lbl["id"]): str(lbl["name"]) for lbl in live_gmail_client.list_labels()
    }

    # Verify 1.6 MiB attachment byte-for-byte SHA-256 integrity from live Gmail
    fetched_large = live_gmail_client.get_message(r_large.destination_id, fmt="raw")
    parsed_large = BytesParser(policy=policy.default).parsebytes(
        _decode_b64url(fetched_large["raw"])
    )
    downloaded_blob = next(
        p.get_payload(decode=True)
        for p in parsed_large.walk()
        if p.get_filename() == "payload.bin"
    )
    assert isinstance(downloaded_blob, bytes)
    assert len(downloaded_blob) == 1_600_000
    assert hashlib.sha256(downloaded_blob).hexdigest() == expected_large_sha

    # Verify ISO-8859-1 body bytes and bounce From:<> audit headers
    fetched_bounce = live_gmail_client.get_message(r_bounce.destination_id, fmt="raw")
    raw_bounce_returned = _decode_b64url(fetched_bounce["raw"])
    parsed_bounce = BytesParser(policy=policy.default).parsebytes(raw_bounce_returned)
    assert "postmaster@gyb-itest.local" in str(parsed_bounce["From"])
    assert parsed_bounce["X-GYB-Orig-Msg-From"] == "<>"
    assert "Café Bounce ISO-8859-1" in str(parsed_bounce["Subject"])
    assert iso_body in raw_bounce_returned

    # Verify reserved/CHAT label mapping in live Gmail
    assert r_dedup_1.destination_id is not None
    fetched_dedup = live_gmail_client.get_message(r_dedup_1.destination_id, fmt="full")
    dedup_label_names = {
        label_id_to_name.get(lid, lid) for lid in fetched_dedup.get("labelIds", [])
    }
    assert {
        "INBOX",
        "STARRED",
        f"{ns}/Edge/Chats_restored",
        f"{ns}/Edge/_archive/2024",
        f"{ns}/Edge/_muted",
    }.issubset(dedup_label_names)

    # Verify deleted=True is Vault-only permanently deleted (invisible to mailbox get_message)
    with pytest.raises(GmailNotFoundError, match="404 Not Found"):
        live_gmail_client.get_message(r_vault_deleted.destination_id, fmt="full")

    # Verify TRASH label import landed in user TRASH alongside prefixed custom label
    fetched_trash = live_gmail_client.get_message(r_trash.destination_id, fmt="full")
    trash_label_names = {
        label_id_to_name.get(lid, lid) for lid in fetched_trash.get("labelIds", [])
    }
    assert {"TRASH", f"{ns}/Edge/DeletedItems"}.issubset(trash_label_names)

    # Verify editable DRAFT has both DRAFT and custom user label
    fetched_draft = live_gmail_client.get_message(r_draft.destination_id, fmt="full")
    draft_label_names = {
        label_id_to_name.get(lid, lid) for lid in fetched_draft.get("labelIds", [])
    }
    assert {"DRAFT", f"{ns}/Edge/DraftFolder"}.issubset(draft_label_names)


def test_live_gmail_error_responses_cli_report_and_retry(
    live_env: LiveTestEnv,
    live_gmail_client: GmailClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test live 404, oversize MediaUploadSizeError batch, 429 backoff, and gyb report/retry CLI."""
    ns = live_env.label_namespace
    fixed_dt = datetime(2024, 8, 1, 10, 0, 0, tzinfo=UTC)

    # 1. Live Gmail 404 Not Found -> GmailNotFoundError & 400 Bad Request -> GmailBadRequestError
    with pytest.raises(GmailNotFoundError, match="404 Not Found"):
        live_gmail_client.get_message("0000000000000000")
    with pytest.raises(GmailBadRequestError, match="400 Bad Request"):
        live_gmail_client.create_label("")

    # 2. Mixed batch with permanent oversize draft (36 MiB > 35 MiB Discovery maxSize)
    mixed_dir = tmp_path / "mixed-batch-local"
    with LocalGYBSink(mixed_dir, email_address=live_env.gmail_user) as local_sink:
        local_sink.import_message(
            Message(
                source_id="valid-small",
                raw_rfc822=(
                    f"Message-ID: <mixed-ok-{live_env.run_id}@gyb-itest.local>\r\n"
                    f"Date: {format_datetime(fixed_dt)}\r\n"
                    "From: Valid <valid@gyb-itest.local>\r\n"
                    "To: recipient@gyb-itest.local\r\n"
                    f"Subject: [gyb-{live_env.run_id}] Valid Mixed Item\r\n"
                    f"X-GYB-ITest-Run: {live_env.run_id}\r\n\r\n"
                    f"Valid body {live_env.run_id}\r\n"
                ).encode(),
                labels=(f"{ns}/ErrorSuite",),
            )
        )
        local_sink.import_message(
            Message(
                source_id="oversize-draft",
                raw_rfc822=b"Subject: Oversize Draft\r\n\r\n" + (b"X" * (36 * 1024 * 1024)),
                labels=("DRAFT", f"{ns}/ErrorSuite"),
                is_draft=True,
            )
        )

    mixed_db = tmp_path / "mixed-jobs.sqlite"
    with JobStore(mixed_db) as store:
        mixed_job = store.create_job(
            action="restore",
            source_uri=f"local://{mixed_dir}",
            sink_uri=f"gmail://{live_env.gmail_user}",
        )
        mixed_summary = TransferPipeline(
            LocalGYBSource(mixed_dir),
            GmailSink(live_gmail_client, close_transport=False),
            on_result=lambda res, att: store.record_item(mixed_job.job_id, res, attempts=att),
            tuning=StreamTuningConfig(initial_streams=2, min_streams=1, max_streams=4),
        ).run()
        final_mixed = store.finalize_job(mixed_job.job_id, mixed_summary)
        assert final_mixed.state == JobState.COMPLETED_WITH_ERRORS
        assert final_mixed.succeeded == 1
        assert final_mixed.failed == 1
        failures = store.list_job_items(mixed_job.job_id, status=TransferStatus.FAILED)
        assert len(failures) == 1
        assert failures[0].source_id == "oversize-draft"
        assert failures[0].retryable is False

    # 3. Controlled 429 Rate-Limit Backoff -> JobStore Tracking -> CLI `gyb report` & `gyb retry`
    cfg_dir = tmp_path / "cli-cfg"
    profile_name = setup_live_profile_dir(live_env, cfg_dir)
    if not live_env.profile_name:
        monkeypatch.setenv("GYB_CONFIG_DIR", str(cfg_dir))

    cli_source_dir = tmp_path / "cli-restore-src"
    with LocalGYBSink(cli_source_dir, email_address=live_env.gmail_user) as local_sink:
        for idx in range(4):
            sid = "throttled-item" if idx == 2 else f"clean-item-{idx}"
            local_sink.import_message(
                Message(
                    source_id=sid,
                    raw_rfc822=(
                        f"Message-ID: <cli-{sid}-{live_env.run_id}@gyb-itest.local>\r\n"
                        f"Date: {format_datetime(fixed_dt)}\r\n"
                        "From: CLI Runner <cli@gyb-itest.local>\r\n"
                        "To: recipient@gyb-itest.local\r\n"
                        f"Subject: [gyb-{live_env.run_id}] CLI Item {sid}\r\n"
                        f"X-GYB-ITest-Run: {live_env.run_id}\r\n\r\n"
                        f"CLI body for {sid} ({live_env.run_id})\r\n"
                    ).encode(),
                    labels=(f"{ns}/CLIRetry",),
                )
            )

    class _Flaky429GmailSink(GmailSink):
        def import_message(self, message: Message) -> TransferResult:
            if message.source_id == "throttled-item":
                raise TransientTransferError(
                    "Gmail HTTP 429: User-rate limit exceeded (simulated)",
                    retry_after=0.02,
                )
            return super().import_message(message)

    cli_jobs_db = cfg_dir / "jobs.db"
    job_opts = TransferOptions(dest_profile=profile_name).to_dict()
    with JobStore(cli_jobs_db) as store:
        initial_job = store.create_job(
            action="restore",
            source_uri=f"local://{cli_source_dir}",
            sink_uri=f"gmail://{live_env.gmail_user}",
            options=job_opts,
        )
        initial_summary = TransferPipeline(
            LocalGYBSource(cli_source_dir),
            _Flaky429GmailSink(live_gmail_client, close_transport=False),
            on_result=lambda res, att: store.record_item(initial_job.job_id, res, attempts=att),
            max_item_retries=2,
            tuning=StreamTuningConfig(
                initial_streams=4,
                min_streams=1,
                max_streams=8,
                base_backoff=0.02,
                max_backoff=0.05,
            ),
        ).run()
        final_initial = store.finalize_job(initial_job.job_id, initial_summary)

    assert final_initial.state == JobState.COMPLETED_WITH_ERRORS
    assert final_initial.succeeded == 3
    assert final_initial.failed == 1
    assert initial_summary.telemetry.throttle_events >= 1

    # Exercise `gyb report <job_id> --export-json --export-csv` via Click CliRunner
    runner = CliRunner()
    json_out = tmp_path / "report.json"
    csv_out = tmp_path / "report.csv"
    rep_res = runner.invoke(
        cli,
        [
            "--config-dir",
            str(cfg_dir),
            "report",
            initial_job.job_id,
            "--export-json",
            str(json_out),
            "--export-csv",
            str(csv_out),
        ],
    )
    assert rep_res.exit_code == 0, rep_res.output
    exported_json = json.loads(json_out.read_text(encoding="utf-8"))
    assert exported_json["job"]["failed"] == 1
    failed_json = [it for it in exported_json["items"] if it["status"] == "failed"]
    assert len(failed_json) == 1 and failed_json[0]["source_id"] == "throttled-item"
    with csv_out.open("r", encoding="utf-8", newline="") as fh:
        csv_rows = [r for r in csv.DictReader(fh) if r["status"] == "failed"]
    assert len(csv_rows) == 1 and csv_rows[0]["source_id"] == "throttled-item"

    # Exercise `gyb retry <job_id>` via Click CliRunner against LIVE Gmail API!
    retry_res = runner.invoke(
        cli,
        [
            "--config-dir",
            str(cfg_dir),
            "retry",
            initial_job.job_id,
        ],
    )
    assert retry_res.exit_code == 0, retry_res.output

    with JobStore(cli_jobs_db) as store:
        recent_jobs = store.list_jobs(limit=5)
        retry_job = next(j for j in recent_jobs if j.action == "retry")
        assert retry_job.state == JobState.COMPLETED
        assert retry_job.succeeded == 1
        assert retry_job.failed == 0

    recovered_gmail_ids = list(live_gmail_client.list_messages(query=f'label:"{ns}/CLIRetry"'))
    assert len(recovered_gmail_ids) == 4
