"""Live integration tests against Google Gmail, Groups Migration, and OAuth/DPoP servers.

Validates HTTP/2 multiplexing (version == 20), post-import mailbox fidelity (RFC 822
headers, multipart bodies, binary attachment SHA-256 digests, system & nested user labels,
internalDate, threadId, drafts, and 400 sanitization), Gmail -> Local GYB -> Gmail
disaster-recovery round-trip, Takeout mbox migration, Google Groups archive upload, and
live DPoP proof signing / negative key-binding checks.
"""

from __future__ import annotations

import base64
import hashlib
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
from cryptography.hazmat.primitives.asymmetric import ec
from dpop_signer_ephemeral import EphemeralDPoPSigner
from google.auth.dpop import SoftwareDPoPSigner
from google.oauth2.dpop_credentials import DPoPCredentials
from tests.integration.conftest import (
    LiveTestEnv,
    build_live_transport,
    load_legacy_gyb_oauth_info,
)

from ngyb.auth import ModernAuthorizedHttp, ProfileManager
from ngyb.core import (
    JobState,
    Message,
    StreamTuningConfig,
    TransferPipeline,
    TransferStatus,
)
from ngyb.modules.gmail import GmailClient, GmailSink, GmailSource
from ngyb.modules.google_groups import GoogleGroupsSink, GroupsMigrationClient
from ngyb.modules.local import LocalGYBSink, LocalGYBSource
from ngyb.modules.mbox import MboxSource

pytestmark = pytest.mark.integration

REPO_SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def _decode_b64url(raw_str: str) -> bytes:
    padded = raw_str + "=" * (-len(raw_str) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _build_multipart_attachment_email(
    run_id: str,
    msg_date: datetime,
    attachment_bytes: bytes,
) -> bytes:
    outer = MIMEMultipart("mixed")
    outer["Message-ID"] = f"<att-{run_id}@ngyb-itest.local>"
    outer["Date"] = format_datetime(msg_date)
    outer["From"] = "NGYB Integration <itest@ngyb-itest.local>"
    outer["To"] = "recipient@ngyb-itest.local"
    outer["Subject"] = f"[ngyb-{run_id}] Multipart Attachment Verification"
    outer["X-NGYB-ITest-Run"] = run_id

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(f"Plain text body for {run_id}", "plain", "utf-8"))
    alt.attach(MIMEText(f"<p>HTML body for <b>{run_id}</b></p>", "html", "utf-8"))
    outer.attach(alt)

    part = MIMEApplication(attachment_bytes, _subtype="octet-stream")
    part.add_header("Content-Disposition", "attachment", filename="payload.bin")
    outer.attach(part)
    return outer.as_bytes(policy=policy.SMTP)


def _build_utf8_email(run_id: str, msg_date: datetime) -> bytes:
    msg = MIMEText(f"Unicode verification body — 東京 / Español — {run_id}", "plain", "utf-8")
    msg["Message-ID"] = f"<utf8-{run_id}@ngyb-itest.local>"
    msg["Date"] = format_datetime(msg_date)
    msg["From"] = f"{Header('佐藤 太郎', 'utf-8').encode()} <taro@ngyb-itest.local>"
    msg["To"] = "recipient@ngyb-itest.local"
    msg["Subject"] = Header(f"[ngyb-{run_id}] 日本語とEspañol検証 ✨", "utf-8").encode()
    msg["X-NGYB-ITest-Run"] = run_id
    return msg.as_bytes(policy=policy.SMTP)


def _build_thread_pair(run_id: str, base_date: datetime) -> tuple[bytes, bytes]:
    root_msgid = f"<thread-root-{run_id}@ngyb-itest.local>"
    reply_msgid = f"<thread-reply-{run_id}@ngyb-itest.local>"
    subj = f"Architecture Thread {run_id}"

    root = MIMEText(f"Thread root message {run_id}", "plain", "utf-8")
    root["Message-ID"] = root_msgid
    root["Date"] = format_datetime(base_date)
    root["From"] = "Alice <alice@ngyb-itest.local>"
    root["To"] = "Bob <bob@ngyb-itest.local>"
    root["Subject"] = subj
    root["X-NGYB-ITest-Run"] = run_id

    reply = MIMEText(f"Thread reply message {run_id}", "plain", "utf-8")
    reply["Message-ID"] = reply_msgid
    reply["Date"] = format_datetime(base_date.replace(minute=(base_date.minute + 1) % 60))
    reply["From"] = "Bob <bob@ngyb-itest.local>"
    reply["To"] = "Alice <alice@ngyb-itest.local>"
    reply["Subject"] = f"Re: {subj}"
    reply["In-Reply-To"] = root_msgid
    reply["References"] = root_msgid
    reply["X-NGYB-ITest-Run"] = run_id
    return root.as_bytes(policy=policy.SMTP), reply.as_bytes(policy=policy.SMTP)


def test_gmail_http2_deep_mailbox_verification_and_roundtrip(
    live_env: LiveTestEnv,
    live_gmail_client: GmailClient,
    tmp_path: Path,
) -> None:
    """Import rich messages concurrently over HTTP/2 and inspect the live mailbox."""
    profile = live_gmail_client.get_profile()
    assert profile.get("emailAddress", "").lower() == live_env.gmail_user.lower()
    assert live_gmail_client.last_http_version == 20, "Expected HTTP/2 (version 20) to Gmail API"

    fixed_dt = datetime(2024, 6, 15, 14, 30, 0, tzinfo=UTC)
    attachment_payload = hashlib.sha512(live_env.run_id.encode("utf-8")).digest() * 64
    expected_sha256 = hashlib.sha256(attachment_payload).hexdigest()

    att_raw = _build_multipart_attachment_email(live_env.run_id, fixed_dt, attachment_payload)
    utf8_raw = _build_utf8_email(live_env.run_id, fixed_dt)
    root_raw, reply_raw = _build_thread_pair(live_env.run_id, fixed_dt)
    draft_raw = (
        f"Message-ID: <draft-{live_env.run_id}@ngyb-itest.local>\r\n"
        f"Date: {format_datetime(fixed_dt)}\r\n"
        "From: Draft Author <draft@ngyb-itest.local>\r\n"
        "To: recipient@ngyb-itest.local\r\n"
        f"Subject: [ngyb-{live_env.run_id}] Draft Verification\r\n\r\n"
        f"Draft body {live_env.run_id}\r\n"
    ).encode()
    # Deliberately malformed message (missing From, broken Message-ID & Date)
    malformed_raw = (
        b"Message-ID: invalid message id with spaces\r\n"
        b"Date: definitely-not-an-rfc2822-date\r\n"
        + f"Subject: [ngyb-{live_env.run_id}] Sanitized Malformed Message\r\n\r\n".encode()
        + f"Malformed test body {live_env.run_id}\r\n".encode()
    )

    ns = live_env.label_namespace
    sink = GmailSink(live_gmail_client, close_transport=False)
    sink.connect()
    try:
        r_att = sink.import_message(
            Message(
                source_id="att",
                raw_rfc822=att_raw,
                labels=("INBOX", "STARRED", "UNREAD", f"{ns}/Attachments"),
            )
        )
        r_utf8 = sink.import_message(
            Message(
                source_id="utf8",
                raw_rfc822=utf8_raw,
                labels=(f"{ns}/Intl",),
            )
        )
        r_root = sink.import_message(
            Message(source_id="root", raw_rfc822=root_raw, labels=(f"{ns}/Threads",))
        )
        r_reply = sink.import_message(
            Message(source_id="reply", raw_rfc822=reply_raw, labels=(f"{ns}/Threads",))
        )
        r_draft = sink.import_message(
            Message(source_id="draft", raw_rfc822=draft_raw, labels=("DRAFT", f"{ns}/Drafts"))
        )
        r_mal = sink.import_message(
            Message(
                source_id="malformed",
                raw_rfc822=malformed_raw,
                internal_date=fixed_dt,
                labels=(f"{ns}/Sanitized",),
            )
        )
    finally:
        sink.close()

    for res in (r_att, r_utf8, r_root, r_reply, r_draft, r_mal):
        assert res.status == TransferStatus.SUCCESS
        assert res.destination_id is not None

    assert live_gmail_client.last_http_version == 20

    # --- Deep Mailbox Inspection ---
    label_id_to_name = {str(lbl["id"]): str(lbl["name"]) for lbl in live_gmail_client.list_labels()}

    # 1. Verify Multipart + Binary Attachment + Labels + internalDate
    assert r_att.destination_id is not None
    fetched_att = live_gmail_client.get_message(r_att.destination_id, fmt="raw")
    parsed_att = BytesParser(policy=policy.default).parsebytes(_decode_b64url(fetched_att["raw"]))
    assert parsed_att["Subject"] == f"[ngyb-{live_env.run_id}] Multipart Attachment Verification"
    assert int(fetched_att["internalDate"]) // 1000 == int(fixed_dt.timestamp())

    att_labels = {label_id_to_name.get(lid, lid) for lid in fetched_att.get("labelIds", [])}
    assert {"INBOX", "STARRED", "UNREAD", f"{ns}/Attachments"}.issubset(att_labels)

    found_plain = False
    found_html = False
    found_bin_sha = None
    for part in parsed_att.walk():
        ctype = part.get_content_type()
        if ctype == "text/plain" and not part.get_filename():
            found_plain = f"Plain text body for {live_env.run_id}" in part.get_content()
        elif ctype == "text/html":
            found_html = f"<b>{live_env.run_id}</b>" in part.get_content()
        elif part.get_filename() == "payload.bin":
            payload_bytes = part.get_payload(decode=True)
            assert isinstance(payload_bytes, bytes)
            found_bin_sha = hashlib.sha256(payload_bytes).hexdigest()

    assert found_plain is True
    assert found_html is True
    assert found_bin_sha == expected_sha256

    # 2. Verify Internationalized UTF-8 / RFC 2047 Headers
    assert r_utf8.destination_id is not None
    fetched_utf8 = live_gmail_client.get_message(r_utf8.destination_id, fmt="raw")
    parsed_utf8 = BytesParser(policy=policy.default).parsebytes(_decode_b64url(fetched_utf8["raw"]))
    assert "日本語とEspañol検証 ✨" in str(parsed_utf8["Subject"])
    assert "佐藤 太郎" in str(parsed_utf8["From"])

    # 3. Verify Conversation Threading in Gmail
    assert r_root.destination_id is not None and r_reply.destination_id is not None
    fetched_root = live_gmail_client.get_message(r_root.destination_id, fmt="full")
    fetched_reply = live_gmail_client.get_message(r_reply.destination_id, fmt="full")
    assert fetched_root["threadId"] == fetched_reply["threadId"]

    # 4. Verify Draft Exists with DRAFT System Label + Custom User Label
    assert r_draft.destination_id is not None
    fetched_draft = live_gmail_client.get_message(r_draft.destination_id, fmt="full")
    draft_labels = {label_id_to_name.get(lid, lid) for lid in fetched_draft.get("labelIds", [])}
    assert {"DRAFT", f"{ns}/Drafts"}.issubset(draft_labels)

    # 5. Verify Malformed Message Exists in Mailbox with GYB Hygiene Audit Headers
    assert r_mal.destination_id is not None
    fetched_mal = live_gmail_client.get_message(r_mal.destination_id, fmt="raw")
    parsed_mal = BytesParser(policy=policy.default).parsebytes(_decode_b64url(fetched_mal["raw"]))
    assert parsed_mal["Message-ID"].endswith("@gyb-restore.local>")
    assert "gyb-restore@gyb-restore.local" in str(parsed_mal["From"])
    assert parsed_mal["X-GYB-Changes-Made"] is not None

    # --- Round-Trip Disaster Recovery: Gmail -> Local GYB -> Delete -> Restore -> Inspect ---
    backup_dir = tmp_path / "live-local-backup"
    tuning = StreamTuningConfig(initial_streams=4, min_streams=1, max_streams=8)
    backup_summary = TransferPipeline(
        GmailSource(live_gmail_client, close_transport=False),
        LocalGYBSink(backup_dir, email_address=live_env.gmail_user),
        tuning=tuning,
    ).run(query=f"label:{ns}/Attachments OR label:{ns}/Intl")
    assert backup_summary.state == JobState.COMPLETED
    assert backup_summary.succeeded == 2

    # Delete original two messages from Gmail so restore creates fresh copies without dedup
    live_gmail_client.delete_message(r_att.destination_id)
    live_gmail_client.delete_message(r_utf8.destination_id)

    restore_prefix = f"{ns}/Restored"
    restore_summary = TransferPipeline(
        LocalGYBSource(backup_dir),
        GmailSink(
            live_gmail_client,
            label_prefix=restore_prefix,
            close_transport=False,
        ),
        tuning=tuning,
    ).run()
    assert restore_summary.state == JobState.COMPLETED
    assert restore_summary.succeeded == 2

    restored_ids = list(
        live_gmail_client.list_messages(query=f"label:{restore_prefix}/{ns}/Attachments")
    )
    assert len(restored_ids) == 1
    restored_raw = _decode_b64url(live_gmail_client.get_message(restored_ids[0], fmt="raw")["raw"])
    restored_parsed = BytesParser(policy=policy.default).parsebytes(restored_raw)
    restored_att = next(
        p.get_payload(decode=True)
        for p in restored_parsed.walk()
        if p.get_filename() == "payload.bin"
    )
    assert isinstance(restored_att, bytes)
    assert hashlib.sha256(restored_att).hexdigest() == expected_sha256


def test_takeout_mbox_to_gmail_and_google_groups(
    live_env: LiveTestEnv,
    live_gmail_client: GmailClient,
    tmp_path: Path,
) -> None:
    """Verify streaming mbox Takeout migration into Gmail and (when configured) Google Groups."""
    ns = live_env.label_namespace
    mbox_path = tmp_path / "takeout_itest.mbox"
    mbox_path.write_bytes(
        f"From 12345@xxx Sat Jun 15 14:30:00 2024\r\n"
        f"Message-ID: <mbox-{live_env.run_id}@ngyb-itest.local>\r\n"
        f"Date: Sat, 15 Jun 2024 14:30:00 +0000\r\n"
        f"From: Takeout Sender <takeout@ngyb-itest.local>\r\n"
        f"To: recipient@ngyb-itest.local\r\n"
        f"Subject: [ngyb-{live_env.run_id}] Takeout Mbox Import\r\n"
        f'X-Gmail-Labels: RECIBIDOS, "{ns}/TakeoutLabel", ^OPENED\r\n\r\n'
        f"Takeout mbox body {live_env.run_id}\r\n\r\n".encode()
    )

    tuning = StreamTuningConfig(initial_streams=4, min_streams=1, max_streams=8)
    summary = TransferPipeline(
        MboxSource(mbox_path),
        GmailSink(live_gmail_client, close_transport=False),
        tuning=tuning,
    ).run()
    assert summary.state == JobState.COMPLETED
    assert summary.succeeded == 1

    found = list(live_gmail_client.list_messages(query=f"label:{ns}/TakeoutLabel"))
    assert len(found) == 1
    msg_data = live_gmail_client.get_message(found[0], fmt="raw")
    assert "INBOX" in msg_data.get("labelIds", [])
    assert f"Takeout mbox body {live_env.run_id}".encode() in _decode_b64url(msg_data["raw"])

    if live_env.group_email:
        grp_transport = build_live_transport(live_env, tmp_path / "grp-cfg")
        try:
            grp_client = GroupsMigrationClient(grp_transport, live_env.group_email)
            grp_sink = GoogleGroupsSink(
                grp_client,
                cleanup=True,
                cleanup_from="God of Thunder <thor@avengers.com>",
                close_transport=False,
            )
            grp_sink.connect()
            try:
                res = grp_sink.import_message(
                    Message(
                        source_id="grp-1",
                        raw_rfc822=(
                            f"Message-ID: <grp-{live_env.run_id}@ngyb-itest.local>\r\n"
                            f"Date: Sat, 15 Jun 2024 14:30:00 +0000\r\n"
                            f"From: Group Tester <tester@ngyb-itest.local>\r\n"
                            f"To: {live_env.group_email}\r\n"
                            f"Subject: [ngyb-{live_env.run_id}] Group Archive Verification\r\n\r\n"
                            f"Group archive payload {live_env.run_id}\r\n"
                        ).encode(),
                    )
                )
                assert res.status == TransferStatus.SUCCESS
                assert grp_client.last_http_version == 20
            finally:
                grp_sink.close()
        finally:
            grp_transport.close()


def test_live_dpop_token_refresh_and_ephemeral_negative_binding(
    live_env: LiveTestEnv,
    tmp_path: Path,
) -> None:
    """Verify live DPoP refresh and negative EphemeralDPoPSigner rejection when configured."""
    if live_env.dpop_profile_name:
        mgr = ProfileManager()
        http = mgr.build_authorized_http(live_env.dpop_profile_name)
        try:
            http.ensure_valid_token(force=True)
            assert isinstance(http.credentials, DPoPCredentials)

            # Negative verification: attempting to refresh a DPoP-bound token with a fresh
            # EphemeralDPoPSigner key MUST be rejected by Google's OAuth 2.0 token server!
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
        finally:
            http.close()
        return

    if live_env.legacy_oauth_cfg and live_env.legacy_oauth_cfg.is_file():
        info = load_legacy_gyb_oauth_info(live_env.legacy_oauth_cfg)
        signer = SoftwareDPoPSigner(ec.generate_private_key(ec.SECP256R1()), key_id="ci-dpop")
        creds = DPoPCredentials(
            token=None,
            dpop_signer=signer,
            refresh_token=info["refresh_token"],
            token_uri=info["token_uri"],
            client_id=info["client_id"],
            client_secret=info["client_secret"],
        )
        transport = ModernAuthorizedHttp(creds, max_streams=4, enable_http2=True)
        try:
            transport.ensure_valid_token(force=True)
            assert creds.valid
            gmail = GmailClient(transport, user_id=live_env.gmail_user)
            prof = gmail.get_profile()
            assert prof.get("emailAddress", "").lower() == live_env.gmail_user.lower()
            assert gmail.last_http_version == 20
        finally:
            transport.close()
        return

    pytest.skip(
        "Set NGYB_ITEST_DPOP_PROFILE or NGYB_ITEST_OAUTH_CFG to run live OAuth/DPoP token tests."
    )
