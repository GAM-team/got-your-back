"""Fixtures and environment configuration for live Google API integration tests."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from gyb.auth import (
    DEFAULT_OAUTH_SCOPES,
    ADCProfile,
    ModernAuthorizedHttp,
    ProfileManager,
    SignerConfig,
)
from gyb.modules.gmail import GmailClient


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
    adc_mode: str | None = None


@pytest.fixture(scope="session")
def live_env() -> LiveTestEnv:
    gmail_user = os.environ.get("GYB_ITEST_GMAIL_USER", "").strip()
    if not gmail_user:
        pytest.skip("Set GYB_ITEST_GMAIL_USER to run live Google API integration tests.")

    run_id = uuid.uuid4().hex[:10]
    legacy_cfg_raw = os.environ.get("GYB_ITEST_OAUTH_CFG", "").strip()
    return LiveTestEnv(
        gmail_user=gmail_user,
        subject=os.environ.get("GYB_ITEST_SUBJECT", "").strip() or gmail_user,
        profile_name=os.environ.get("GYB_ITEST_PROFILE", "").strip() or None,
        group_email=os.environ.get("GYB_ITEST_GROUP_EMAIL", "").strip() or None,
        dpop_profile_name=os.environ.get("GYB_ITEST_DPOP_PROFILE", "").strip() or None,
        legacy_oauth_cfg=Path(legacy_cfg_raw) if legacy_cfg_raw else None,
        run_id=run_id,
        label_namespace=f"gyb-itest-{run_id}",
        adc_mode=os.environ.get("GYB_ITEST_ADC_MODE", "").strip().lower() or None,
    )


def setup_live_profile_dir(env: LiveTestEnv, config_dir: Path) -> str:
    """Ensure a valid GYB auth profile exists in ``config_dir`` and return its name."""
    if env.profile_name:
        return env.profile_name
    mgr = ProfileManager(config_dir)
    profile_name = "itest-adc"
    adc_prof = ADCProfile(
        name=profile_name,
        scopes=DEFAULT_OAUTH_SCOPES,
        subject=env.subject,
        signer=SignerConfig(key_id="itest-adc"),
    )
    mgr.save_profile(adc_prof)
    return profile_name


def build_live_transport(
    env: LiveTestEnv,
    tmp_config_dir: Path,
    *,
    max_streams: int = 16,
) -> ModernAuthorizedHttp:
    """Create a ModernAuthorizedHttp transport for live Google API tests."""
    profile_name = setup_live_profile_dir(env, tmp_config_dir)
    mgr = ProfileManager(None if env.profile_name else tmp_config_dir)
    return mgr.build_authorized_http(
        profile_name,
        scopes=DEFAULT_OAUTH_SCOPES,
        max_streams=max_streams,
        enable_http2=True,
    )


@pytest.fixture()
def live_gmail_client(
    live_env: LiveTestEnv,
    tmp_path: Path,
) -> Iterator[GmailClient]:
    """Provide an HTTP/2 GmailClient and guarantee safe post-test message & label cleanup."""
    transport = build_live_transport(live_env, tmp_path / "itest-cfg")
    client = GmailClient(transport, user_id=live_env.gmail_user)
    preexisting_ids = set(client.list_messages(include_spam_trash=True))
    try:
        yield client
    finally:
        try:
            prefix = live_env.label_namespace.lower()
            labels = client.list_labels()
            matching_labels = sorted(
                (lbl for lbl in labels if str(lbl.get("name", "")).lower().startswith(prefix)),
                key=lambda item: len(str(item.get("name", ""))),
                reverse=True,
            )

            candidate_msg_ids: set[str] = set(
                client.list_messages(query=live_env.run_id, include_spam_trash=True)
            )
            for lbl in matching_labels:
                lbl_name = str(lbl.get("name", ""))
                if lbl_name:
                    escaped = lbl_name.replace('"', '\\"')
                    candidate_msg_ids.update(
                        client.list_messages(
                            query=f'label:"{escaped}"',
                            include_spam_trash=True,
                        )
                    )

            for mid in candidate_msg_ids - preexisting_ids:
                try:
                    client.delete_message(mid)
                except Exception:
                    pass

            for lbl in matching_labels:
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
