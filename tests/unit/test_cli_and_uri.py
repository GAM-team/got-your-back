"""Unit tests for URI parsing, stream options, and all Click CLI subcommands."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from google.oauth2.dpop_credentials import DPoPCredentials
from tests.unit.test_module_gmail import QueuedTransport

from gyb.auth import ProfileManager
from gyb.cli import cli
from gyb.cli.options import TransferOptions
from gyb.cli.uri import (
    build_sink_from_spec,
    build_source_from_spec,
    parse_endpoint,
)
from gyb.core import (
    ConfigurationError,
    Message,
    StreamTuningConfig,
    TransferResult,
    TransferStatus,
)
from gyb.db import JobStore
from gyb.modules.gmail import GmailSink, GmailSource
from gyb.modules.google_groups import GoogleGroupsSink
from gyb.modules.local import LocalGYBSink

REPO_SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def test_uri_parsing_and_endpoint_builders(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    opts_roundtrip = TransferOptions(
        source_profile="sp",
        dest_profile="dp",
        cleanup=True,
        preserve_threads=True,
    )
    assert TransferOptions.from_dict(opts_roundtrip.to_dict()) == opts_roundtrip

    with pytest.raises(ConfigurationError, match="cannot be empty"):
        parse_endpoint("   ", for_source=True)
    with pytest.raises(ConfigurationError, match="Unsupported endpoint scheme"):
        parse_endpoint("imap://mail.example.com", for_source=True)
    with pytest.raises(ConfigurationError, match="Missing target"):
        parse_endpoint("gmail://   ", for_source=True)

    g_spec = parse_endpoint("gmail://alice@example.com", for_source=True)
    assert g_spec.uri == "gmail://alice@example.com"
    grp_spec = parse_endpoint("group://team@example.com", for_source=False)
    assert grp_spec.uri == "groups://team@example.com"
    loc_uri = parse_endpoint(f"local://{tmp_path / 'arch'}", for_source=False)
    assert loc_uri.scheme == "local"

    shorthand = parse_endpoint("bob@example.com", for_source=True, default_email_scheme="gmail")
    assert shorthand.uri == "gmail://bob@example.com"

    mbox_spec = parse_endpoint(
        str(REPO_SAMPLES / "google-takeout" / "takeout.mbox"), for_source=True
    )
    assert mbox_spec.scheme == "mbox"
    vault_dir_spec = parse_endpoint(str(REPO_SAMPLES / "vault-export-mbox"), for_source=True)
    assert vault_dir_spec.scheme == "mbox"
    gyb_dir_spec = parse_endpoint(str(REPO_SAMPLES / "gyb-format"), for_source=True)
    assert gyb_dir_spec.scheme == "local"

    mgr = ProfileManager(tmp_path / "cfg")
    tuning = StreamTuningConfig()
    default_opts = TransferOptions()
    with pytest.raises(ConfigurationError, match="cannot be used as a mail Source"):
        build_source_from_spec(
            grp_spec,
            profile_manager=mgr,
            options=default_opts,
            tuning=tuning,
        )
    with pytest.raises(ConfigurationError, match="cannot be used as a mail Sink"):
        build_sink_from_spec(
            mbox_spec,
            profile_manager=mgr,
            options=default_opts,
            tuning=tuning,
        )

    fake_tr = QueuedTransport()
    monkeypatch.setattr(mgr, "build_authorized_http", lambda *a, **kw: fake_tr)
    g_src = build_source_from_spec(
        g_spec,
        profile_manager=mgr,
        options=default_opts,
        tuning=tuning,
    )
    assert isinstance(g_src, GmailSource)
    g_src_prof = build_source_from_spec(
        g_spec,
        profile_manager=mgr,
        options=TransferOptions(source_profile="prof1"),
        tuning=tuning,
    )
    assert isinstance(g_src_prof, GmailSource)

    g_sink = build_sink_from_spec(
        g_spec,
        profile_manager=mgr,
        options=default_opts,
        tuning=tuning,
    )
    assert isinstance(g_sink, GmailSink)
    g_sink_prof = build_sink_from_spec(
        g_spec,
        profile_manager=mgr,
        options=TransferOptions(dest_profile="prof1"),
        tuning=tuning,
    )
    assert isinstance(g_sink_prof, GmailSink)

    grp_sink = build_sink_from_spec(
        grp_spec,
        profile_manager=mgr,
        options=TransferOptions(dest_subject="admin@example.com"),
        tuning=tuning,
    )
    assert isinstance(grp_sink, GoogleGroupsSink)


def test_cli_migrate_backup_restore_retry_and_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CliRunner()
    cfg_dir = tmp_path / "cfg"
    base_args = ["--config-dir", str(cfg_dir)]

    res_ver = runner.invoke(cli, ["--version"])
    assert res_ver.exit_code == 0
    assert "gyb, version 2.0.0" in res_ver.output

    bad_tune = runner.invoke(
        cli,
        [*base_args, "backup", "u@example.com", "--min-streams", "0"],
    )
    assert bad_tune.exit_code != 0
    assert "min_streams must be >= 1" in bad_tune.output

    bad_restore = runner.invoke(
        cli,
        [*base_args, "restore", "bad://uri", "u@example.com"],
    )
    assert bad_restore.exit_code != 0

    bad_migrate = runner.invoke(
        cli,
        [*base_args, "migrate", "bad://uri", "u@example.com"],
    )
    assert bad_migrate.exit_code != 0

    local_dest = tmp_path / "local-archive"
    mig_res = runner.invoke(
        cli,
        [
            *base_args,
            "migrate",
            str(REPO_SAMPLES / "google-takeout" / "takeout.mbox"),
            str(local_dest),
        ],
    )
    assert mig_res.exit_code == 0, mig_res.output
    assert "Job Summary" in mig_res.output

    mig_res_2 = runner.invoke(
        cli,
        [
            *base_args,
            "migrate",
            str(REPO_SAMPLES / "google-takeout" / "takeout.mbox"),
            str(local_dest),
        ],
    )
    assert mig_res_2.exit_code == 0

    hist_res = runner.invoke(cli, [*base_args, "report"])
    assert hist_res.exit_code == 0

    with JobStore(cfg_dir / "jobs.db") as js:
        jobs = js.list_jobs()
    first_job_id = jobs[0].job_id

    json_file = tmp_path / "out.json"
    csv_file = tmp_path / "out.csv"
    assert runner.invoke(cli, [*base_args, "report", first_job_id]).exit_code == 0
    rep_res = runner.invoke(
        cli,
        [
            *base_args,
            "report",
            first_job_id,
            "--export-json",
            str(json_file),
            "--export-csv",
            str(csv_file),
        ],
    )
    assert rep_res.exit_code == 0
    assert json_file.is_file() and csv_file.is_file()

    rep_missing = runner.invoke(cli, [*base_args, "report", "nonexistent"])
    assert rep_missing.exit_code != 0

    retry_clean = runner.invoke(cli, [*base_args, "retry", first_job_id])
    assert retry_clean.exit_code == 0
    assert "no failed items" in retry_clean.output

    retry_missing = runner.invoke(cli, [*base_args, "retry", "nonexistent"])
    assert retry_missing.exit_code != 0

    missing_backup = runner.invoke(
        cli,
        [*base_args, "backup", f"local://{tmp_path / 'no-such-src'}", str(tmp_path / "dst")],
    )
    assert missing_backup.exit_code != 0

    flaky_calls = {"failed_once": False}
    orig_import = LocalGYBSink.import_message

    def _flaky_import(self: LocalGYBSink, message: Message) -> TransferResult:
        if not flaky_calls["failed_once"]:
            flaky_calls["failed_once"] = True
            return TransferResult(
                source_id=message.source_id,
                status=TransferStatus.FAILED,
                error_message="disk full",
                retryable=False,
            )
        return orig_import(self, message)

    monkeypatch.setattr(LocalGYBSink, "import_message", _flaky_import)
    restore_target = tmp_path / "restored-local"
    restore_fail = runner.invoke(
        cli,
        [*base_args, "restore", str(local_dest), f"local://{restore_target}"],
    )
    assert restore_fail.exit_code != 0
    assert "failed message(s)" in restore_fail.output
    monkeypatch.undo()

    with JobStore(cfg_dir / "jobs.db") as js2:
        failed_job_id = next(j.job_id for j in js2.list_jobs() if j.failed > 0)

    retry_ok = runner.invoke(cli, [*base_args, "retry", failed_job_id])
    assert retry_ok.exit_code == 0, retry_ok.output


def test_cli_auth_subcommands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()
    cfg_dir = tmp_path / "auth-cfg"
    base = ["--config-dir", str(cfg_dir), "auth"]

    assert runner.invoke(cli, [*base, "signers"]).exit_code == 0

    secrets = tmp_path / "secrets.json"
    secrets.write_text("{}")

    bad_sig = runner.invoke(
        cli,
        [*base, "setup-oauth", "p1", "--client-secrets", str(secrets), "--signer", "bogus"],
    )
    assert bad_sig.exit_code != 0

    def _fake_flow(
        client_secrets_file: Path,
        signer: Any,
        **_: Any,
    ) -> DPoPCredentials:
        _ = client_secrets_file
        return DPoPCredentials(
            token="t",
            dpop_signer=signer,
            refresh_token="r",
            token_uri="https://oauth2.googleapis.com/token",
            client_id="cid",
            client_secret="csec",
            scopes=["email"],
        )

    monkeypatch.setattr("gyb.auth.manager.run_dpop_oauth_flow", _fake_flow)
    ok_oauth = runner.invoke(
        cli,
        [
            *base,
            "setup-oauth",
            "work",
            "--client-secrets",
            str(secrets),
            "--email",
            "alice@example.com",
            "--no-browser",
        ],
    )
    assert ok_oauth.exit_code == 0, ok_oauth.output

    monkeypatch.undo()
    missing_sec = runner.invoke(
        cli,
        [*base, "setup-oauth", "p2", "--client-secrets", str(tmp_path / "missing.json")],
    )
    assert missing_sec.exit_code != 0

    assert runner.invoke(cli, [*base, "setup-adc", "a1", "--signer", "bogus"]).exit_code != 0
    assert (
        runner.invoke(
            cli,
            [*base, "setup-adc", "sa-dwd", "--subject", "bob@example.com", "--signer", "software"],
        ).exit_code
        == 0
    )
    assert runner.invoke(cli, [*base, "setup-adc", "sa-plain"]).exit_code == 0
    assert runner.invoke(cli, [*base, "setup-adc", "../bad"]).exit_code != 0

    list_res = runner.invoke(cli, [*base, "list"])
    assert list_res.exit_code == 0
    assert "work" in list_res.output and "sa-dwd" in list_res.output

    assert runner.invoke(cli, [*base, "info", "work"]).exit_code == 0
    assert runner.invoke(cli, [*base, "info", "sa-plain"]).exit_code == 0
    assert runner.invoke(cli, [*base, "info", "missing"]).exit_code != 0

    assert runner.invoke(cli, [*base, "delete", "sa-plain"]).exit_code == 0
    assert runner.invoke(cli, [*base, "delete", "sa-plain"]).exit_code != 0
