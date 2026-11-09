"""Mandatory DPoP OAuth 2.0 installed-app flows and credential loading."""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

from google.auth.dpop import DPoPSigner
from google.oauth2.dpop_credentials import DPoPCredentials
from google_auth_oauthlib.flow import InstalledAppFlow

from gyb.auth.models import OAuthProfile
from gyb.core.exceptions import AuthenticationError

GMAIL_FULL_SCOPE = "https://mail.google.com/"
GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
GROUPS_MIGRATION_SCOPE = "https://www.googleapis.com/auth/apps.groups.migration"
EMAIL_SCOPE = "email"

DEFAULT_OAUTH_SCOPES: tuple[str, ...] = (
    GMAIL_FULL_SCOPE,
    GROUPS_MIGRATION_SCOPE,
    EMAIL_SCOPE,
)


def run_dpop_oauth_flow(
    client_secrets_file: Path,
    signer: DPoPSigner,
    *,
    scopes: Sequence[str] = DEFAULT_OAUTH_SCOPES,
    login_hint: str | None = None,
    open_browser: bool = True,
    port: int = 0,
) -> DPoPCredentials:
    """Execute loopback InstalledAppFlow bound to a mandatory DPoPSigner."""
    if not client_secrets_file.is_file():
        raise AuthenticationError(f"Client secrets file not found: {client_secrets_file}")

    os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")
    try:
        flow = InstalledAppFlow.from_client_secrets_file(
            str(client_secrets_file),
            scopes=list(scopes),
            dpop_signer=signer,
        )
        kwargs: dict[str, Any] = {
            "port": port,
            "open_browser": open_browser,
            "access_type": "offline",
            "prompt": "consent",
        }
        if login_hint is not None:
            kwargs["login_hint"] = login_hint
        creds = flow.run_local_server(**kwargs)
    except Exception as exc:
        raise AuthenticationError(f"DPoP OAuth authorization flow failed: {exc}") from exc

    if not isinstance(creds, DPoPCredentials):
        raise AuthenticationError(
            "OAuth flow did not return DPoPCredentials; unbound OAuth tokens are forbidden."
        )
    return creds


def serialize_dpop_credentials(creds: DPoPCredentials) -> dict[str, Any]:
    """Serialize DPoPCredentials to a JSON-compatible dictionary without private keys."""
    if creds.dpop_signer is None:
        raise AuthenticationError("Cannot serialize DPoPCredentials without a bound DPoPSigner.")
    return dict(json.loads(creds.to_json()))


def load_dpop_oauth_credentials(
    profile: OAuthProfile,
    signer: DPoPSigner,
) -> DPoPCredentials:
    """Rehydrate DPoPCredentials from an OAuthProfile, verifying key thumbprint binding."""
    try:
        return cast(
            DPoPCredentials,
            DPoPCredentials.from_authorized_user_info(
                profile.authorized_user_info,
                scopes=list(profile.scopes),
                dpop_signer=signer,
            ),
        )
    except ValueError as exc:
        raise AuthenticationError(f"Invalid or mismatched DPoP OAuth credentials: {exc}") from exc
