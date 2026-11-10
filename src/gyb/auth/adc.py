"""Application Default Credentials (ADC) loader with Domain-Wide Delegation and DPoP binding."""

from __future__ import annotations

from collections.abc import Sequence

import google.auth
import google.auth.credentials
import google.auth.exceptions
import google.oauth2.credentials
from google.auth import impersonated_credentials
from google.auth.dpop import DPoPSigner
from google.oauth2.dpop_credentials import DPoPCredentials

from gyb.auth.models import ADCProfile
from gyb.core.exceptions import AuthenticationError


def _delegate_to_subject(
    creds: google.auth.credentials.Credentials,
    subject: str,
    scopes: Sequence[str],
) -> google.auth.credentials.Credentials:
    """Apply Domain-Wide Delegation to ``creds`` for ``subject``.

    Service account key credentials sign the DwD JWT locally via ``with_subject()``.
    Keyless ADC types (Workload Identity Federation ``external_account`` with service
    account impersonation, and ``impersonated_service_account``) have no local private
    key, so the DwD JWT is signed by the IAM Credentials ``signJwt`` API instead. The
    target service account therefore needs ``roles/iam.serviceAccountTokenCreator`` on
    itself.
    """
    with_subject = getattr(creds, "with_subject", None)
    if callable(with_subject):
        delegated: google.auth.credentials.Credentials = with_subject(subject)
        return delegated

    sa_email = getattr(creds, "service_account_email", None)
    if not isinstance(sa_email, str) or "@" not in sa_email:
        raise AuthenticationError(
            f"ADC credential type {type(creds).__name__} does not support "
            f"Domain-Wide Delegation subject {subject!r}: no service account identity "
            "to sign the delegation JWT. Configure Workload Identity Federation with "
            "service account impersonation, or an impersonated service account."
        )
    return impersonated_credentials.Credentials(
        source_credentials=creds,
        target_principal=sa_email,
        target_scopes=list(scopes),
        subject=subject,
        quota_project_id=getattr(creds, "quota_project_id", None),
    )


def load_adc_credentials(
    profile: ADCProfile,
    *,
    signer: DPoPSigner | None = None,
    subject_override: str | None = None,
) -> google.auth.credentials.Credentials:
    """Load Google Application Default Credentials.

    Supports Service Account JSON via ``GOOGLE_APPLICATION_CREDENTIALS``, GCE metadata
    server, Workload Identity Federation (WIF), and impersonated service accounts. When
    ``subject`` is configured, applies Domain-Wide Delegation (see
    :func:`_delegate_to_subject`). When ADC resolves to end-user OAuth credentials,
    upgrades them to ``DPoPCredentials`` bound to ``signer``.
    """
    try:
        creds, _ = google.auth.default(scopes=list(profile.scopes))
    except google.auth.exceptions.DefaultCredentialsError as exc:
        raise AuthenticationError(f"Unable to load Application Default Credentials: {exc}") from exc

    effective_subject = subject_override if subject_override is not None else profile.subject
    if effective_subject is not None:
        creds = _delegate_to_subject(creds, effective_subject, profile.scopes)

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
