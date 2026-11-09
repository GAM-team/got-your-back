"""Mandatory DPoP authentication, OS-scoped signers, ADC, and HTTP/2 transport."""

from gyb.auth.adc import load_adc_credentials
from gyb.auth.manager import ProfileManager, default_config_dir
from gyb.auth.models import (
    ADCProfile,
    AuthProfile,
    OAuthProfile,
    ProfileKind,
    SignerConfig,
    SignerType,
    profile_from_dict,
)
from gyb.auth.oauth import (
    DEFAULT_OAUTH_SCOPES,
    EMAIL_SCOPE,
    GMAIL_FULL_SCOPE,
    GMAIL_READONLY_SCOPE,
    GROUPS_MIGRATION_SCOPE,
    load_dpop_oauth_credentials,
    run_dpop_oauth_flow,
    serialize_dpop_credentials,
)
from gyb.auth.signers import (
    ThreadSafeDPoPSigner,
    available_signer_types,
    build_dpop_signer,
    ensure_software_pem_key,
)
from gyb.auth.transport import ModernAuthorizedHttp, compute_pool_maxsize

__all__ = [
    "ADCProfile",
    "AuthProfile",
    "DEFAULT_OAUTH_SCOPES",
    "EMAIL_SCOPE",
    "GMAIL_FULL_SCOPE",
    "GMAIL_READONLY_SCOPE",
    "GROUPS_MIGRATION_SCOPE",
    "ModernAuthorizedHttp",
    "OAuthProfile",
    "ProfileKind",
    "ProfileManager",
    "SignerConfig",
    "SignerType",
    "ThreadSafeDPoPSigner",
    "available_signer_types",
    "build_dpop_signer",
    "compute_pool_maxsize",
    "default_config_dir",
    "ensure_software_pem_key",
    "load_adc_credentials",
    "load_dpop_oauth_credentials",
    "profile_from_dict",
    "run_dpop_oauth_flow",
    "serialize_dpop_credentials",
]
