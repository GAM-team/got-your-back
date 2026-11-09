"""Fixtures and environment configuration for live Google API integration tests."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from ngyb.auth import (
    DEFAULT_OAUTH_SCOPES,
    ADCProfile,
    ModernAuthorizedHttp,
    ProfileManager,
    SignerConfig,
)
from ngyb.modules.gmail import GmailClient


@dataclass(frozen=True, slots=True)
class LiveTestEnv:
    """Resolved live integration test targets and credentials."""

    gmail_user: str
    subject: str | None
    profile_name: str | None
    group_email: str | None
    dpop_profile_name: str | None
    legacy_oauth_cfg: Path | None
    run_id: str
    label_namespace: str


@pytest.fixture(scope="session")
def live_env() -> LiveTestEnv:
    gmail_user = os.environ.get("NGYB_ITEST_GMAIL_USER", "").strip()
    if not gmail_user:
        pytest.skip("Set NGYB_ITEST_GMAIL_USER to run live Google API integration tests.")

    run_id = uuid.uuid4().hex[:10]
    legacy_cfg_raw = os.environ.get("NGYB_ITEST_OAUTH_CFG", "").strip()
    return LiveTestEnv(
        gmail_user=gmail_user,
        subject=os.environ.get("NGYB_ITEST_SUBJECT", "").strip() or gmail_user,
        profile_name=os.environ.get("NGYB_ITEST_PROFILE", "").strip() or None,
        group_email=os.environ.get("NGYB_ITEST_GROUP_EMAIL", "").strip() or None,
        dpop_profile_name=os.environ.get("NGYB_ITEST_DPOP_PROFILE", "").strip() or None,
        legacy_oauth_cfg=Path(legacy_cfg_raw) if legacy_cfg_raw else None,
        run_id=run_id,
        label_namespace=f"ngyb-itest-{run_id}",
    )


def build_live_transport(
    env: LiveTestEnv,
    tmp_config_dir: Path,
    *,
    max_streams: int = 16,
) -> ModernAuthorizedHttp:
    """Create a ModernAuthorizedHttp transport for live Google API tests."""
    mgr = ProfileManager(tmp_config_dir)
    if env.profile_name:
        return mgr.build_authorized_http(
            env.profile_name,
            scopes=DEFAULT_OAUTH_SCOPES,
            max_streams=max_streams,
            enable_http2=True,
        )

    adc_prof = ADCProfile(
        name="itest-adc",
        scopes=DEFAULT_OAUTH_SCOPES,
        subject=env.subject,
        signer=SignerConfig(key_id="itest-adc"),
    )
    mgr.save_profile(adc_prof)
    return mgr.build_authorized_http(
        "itest-adc",
        scopes=DEFAULT_OAUTH_SCOPES,
        max_streams=max_streams,
        enable_http2=True,
    )


@pytest.fixture()
def live_gmail_client(
    live_env: LiveTestEnv,
    tmp_path: Path,
) -> Iterator[GmailClient]:
    """Provide an HTTP/2 GmailClient and guarantee post-test message & label cleanup."""
    transport = build_live_transport(live_env, tmp_path / "itest-cfg")
    client = GmailClient(transport, user_id=live_env.gmail_user)
    try:
        yield client
    finally:
        try:
            # Clean up any messages matching our unique run_id header/subject token
            msg_ids = list(
                client.list_messages(
                    query=live_env.run_id,
                    include_spam_trash=True,
                )
            )
            for mid in msg_ids:
                try:
                    client.delete_message(mid)
                except Exception:
                    pass

            # Clean up all labels under our unique namespace (deepest children first)
            prefix = live_env.label_namespace.lower()
            labels = client.list_labels()
            matching = sorted(
                (lbl for lbl in labels if str(lbl.get("name", "")).lower().startswith(prefix)),
                key=lambda item: len(str(item.get("name", ""))),
                reverse=True,
            )
            for lbl in matching:
                try:
                    client.delete_label(str(lbl["id"]))
                except Exception:
                    pass
        finally:
            transport.close()


def load_legacy_gyb_oauth_info(cfg_path: Path) -> dict[str, str]:
    """Read legacy GYB .cfg OAuth JSON when running in GAM-team GitHub Actions."""
    data = json.loads(cfg_path.read_text(encoding="utf-8"))
    return {
        "refresh_token": str(data["refresh_token"]),
        "token_uri": str(data.get("token_uri", "https://oauth2.googleapis.com/token")),
        "client_id": str(data["client_id"]),
        "client_secret": str(data["client_secret"]),
    }
