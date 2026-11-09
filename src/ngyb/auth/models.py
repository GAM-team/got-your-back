"""Authentication and DPoP signer configuration models."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ngyb.core.exceptions import ConfigurationError


class ProfileKind(StrEnum):
    """Supported authentication profile types."""

    OAUTH = "oauth"
    ADC = "adc"


class SignerType(StrEnum):
    """Supported DPoP proof-of-possession signer backends."""

    SOFTWARE = "software"
    MACOS_SE = "macos-se"
    WINDOWS_TPM = "windows-tpm"
    LINUX_TPM = "linux-tpm"
    ECP = "ecp"
    YUBIKEY = "yubikey"
    FIDO2 = "fido2"


@dataclass(slots=True)
class SignerConfig:
    """Serializable non-secret configuration for a DPoP signer."""

    signer_type: SignerType = SignerType.SOFTWARE
    key_id: str | None = None
    pem_path: str | None = None
    label: str | None = None
    subject: str | None = None
    cert_thumbprint: str | None = None
    tpm_handle: int | None = None
    ecp_config_path: str | None = None
    piv_slot: str | None = None
    yubikey_serial: int | None = None
    fido2_credential_data: dict[str, Any] | None = None
    dpop_thumbprint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize non-null signer metadata for profile storage."""
        payload: dict[str, Any] = {"signer_type": self.signer_type.value}
        optional_fields = (
            ("key_id", self.key_id),
            ("pem_path", self.pem_path),
            ("label", self.label),
            ("subject", self.subject),
            ("cert_thumbprint", self.cert_thumbprint),
            ("tpm_handle", self.tpm_handle),
            ("ecp_config_path", self.ecp_config_path),
            ("piv_slot", self.piv_slot),
            ("yubikey_serial", self.yubikey_serial),
            ("fido2_credential_data", self.fido2_credential_data),
            ("dpop_thumbprint", self.dpop_thumbprint),
        )
        for key, value in optional_fields:
            if value is not None:
                payload[key] = value
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SignerConfig:
        """Deserialize a SignerConfig from stored profile JSON."""
        try:
            signer_type = SignerType(str(data["signer_type"]))
        except (KeyError, ValueError) as exc:
            raise ConfigurationError(f"Invalid signer_type in profile: {exc}") from exc

        tpm_raw = data.get("tpm_handle")
        yk_raw = data.get("yubikey_serial")
        fido_raw = data.get("fido2_credential_data")
        return cls(
            signer_type=signer_type,
            key_id=data.get("key_id"),
            pem_path=data.get("pem_path"),
            label=data.get("label"),
            subject=data.get("subject"),
            cert_thumbprint=data.get("cert_thumbprint"),
            tpm_handle=int(tpm_raw) if tpm_raw is not None else None,
            ecp_config_path=data.get("ecp_config_path"),
            piv_slot=data.get("piv_slot"),
            yubikey_serial=int(yk_raw) if yk_raw is not None else None,
            fido2_credential_data=dict(fido_raw) if isinstance(fido_raw, Mapping) else None,
            dpop_thumbprint=data.get("dpop_thumbprint"),
        )


@dataclass(slots=True)
class OAuthProfile:
    """DPoP-bound OAuth 2.0 end-user authentication profile."""

    name: str
    scopes: tuple[str, ...]
    signer: SignerConfig
    authorized_user_info: dict[str, Any]
    email: str | None = None
    kind: ProfileKind = ProfileKind.OAUTH

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "name": self.name,
            "email": self.email,
            "scopes": list(self.scopes),
            "signer": self.signer.to_dict(),
            "authorized_user_info": dict(self.authorized_user_info),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> OAuthProfile:
        try:
            signer_data = data["signer"]
            user_info = data["authorized_user_info"]
            name = str(data["name"])
            scopes = tuple(str(s) for s in data["scopes"])
        except (KeyError, TypeError) as exc:
            raise ConfigurationError(f"Malformed OAuth profile: {exc}") from exc

        return cls(
            name=name,
            email=data.get("email"),
            scopes=scopes,
            signer=SignerConfig.from_dict(signer_data),
            authorized_user_info=dict(user_info),
        )


@dataclass(slots=True)
class ADCProfile:
    """Application Default Credentials profile (Service Account, DwD, GCE, WIF)."""

    name: str
    scopes: tuple[str, ...]
    subject: str | None = None
    signer: SignerConfig | None = None
    kind: ProfileKind = ProfileKind.ADC

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": self.kind.value,
            "name": self.name,
            "scopes": list(self.scopes),
        }
        if self.subject is not None:
            payload["subject"] = self.subject
        if self.signer is not None:
            payload["signer"] = self.signer.to_dict()
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ADCProfile:
        try:
            name = str(data["name"])
            scopes = tuple(str(s) for s in data["scopes"])
        except (KeyError, TypeError) as exc:
            raise ConfigurationError(f"Malformed ADC profile: {exc}") from exc

        signer_raw = data.get("signer")
        return cls(
            name=name,
            scopes=scopes,
            subject=data.get("subject"),
            signer=SignerConfig.from_dict(signer_raw) if isinstance(signer_raw, Mapping) else None,
        )


AuthProfile = OAuthProfile | ADCProfile


def profile_from_dict(data: Mapping[str, Any]) -> AuthProfile:
    """Parse either an OAuthProfile or ADCProfile from dictionary data."""
    kind = data.get("kind")
    if kind == ProfileKind.OAUTH.value:
        return OAuthProfile.from_dict(data)
    if kind == ProfileKind.ADC.value:
        return ADCProfile.from_dict(data)
    raise ConfigurationError(f"Unknown authentication profile kind: {kind!r}")
