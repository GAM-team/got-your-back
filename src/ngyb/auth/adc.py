"""Application Default Credentials (ADC) loader with Domain-Wide Delegation and DPoP binding."""

from __future__ import annotations

import google.auth
import google.auth.credentials
import google.auth.exceptions
import google.oauth2.credentials
from google.auth.dpop import DPoPSigner
from google.oauth2.dpop_credentials import DPoPCredentials

from ngyb.auth.models import ADCProfile
from ngyb.core.exceptions import AuthenticationError


def load_adc_credentials(
    profile: ADCProfile,
    *,
    signer: DPoPSigner | None = None,
    subject_override: str | None = None,
) -> google.auth.credentials.Credentials:
    """Load Google Application Default Credentials.

    Supports Service Account JSON via ``GOOGLE_APPLICATION_CREDENTIALS``, GCE metadata
    server, and Workload Identity Federation (WIF). When ``subject`` is configured,
    applies Domain-Wide Delegation via ``with_subject()``. When ADC resolves to end-user
    OAuth credentials, upgrades them to ``DPoPCredentials`` bound to ``signer``.
    """
    try:
        creds, _ = google.auth.default(scopes=list(profile.scopes))
    except google.auth.exceptions.DefaultCredentialsError as exc:
        raise AuthenticationError(f"Unable to load Application Default Credentials: {exc}") from exc

    effective_subject = subject_override if subject_override is not None else profile.subject
    if effective_subject is not None:
        with_subject = getattr(creds, "with_subject", None)
        if not callable(with_subject):
            raise AuthenticationError(
                f"ADC credential type {type(creds).__name__} does not support "
                f"Domain-Wide Delegation subject {effective_subject!r}."
            )
        creds = with_subject(effective_subject)

    if isinstance(creds, google.oauth2.credentials.Credentials) and not isinstance(
        creds, DPoPCredentials
    ):
        if signer is None:
            raise AuthenticationError(
                "ADC resolved to end-user OAuth credentials, which require a DPoP signer."
            )
        creds = DPoPCredentials(
            creds.token,
            dpop_signer=signer,
            refresh_token=creds.refresh_token,
            id_token=creds.id_token,
            token_uri=creds.token_uri,
            client_id=creds.client_id,
            client_secret=creds.client_secret,
            scopes=creds.scopes,
            quota_project_id=creds.quota_project_id,
        )

    return creds
