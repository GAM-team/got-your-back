"""Profile persistence and ModernAuthorizedHttp factory for GYB."""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from pathlib import Path

import google.auth.credentials
from google.oauth2.dpop_credentials import DPoPCredentials

from gyb.auth.adc import load_adc_credentials
from gyb.auth.models import (
    ADCProfile,
    AuthProfile,
    OAuthProfile,
    SignerConfig,
    profile_from_dict,
)
from gyb.auth.oauth import (
    DEFAULT_OAUTH_SCOPES,
    load_dpop_oauth_credentials,
    run_dpop_oauth_flow,
    serialize_dpop_credentials,
)
from gyb.auth.signers import build_dpop_signer
from gyb.auth.transport import ModernAuthorizedHttp
from gyb.core.exceptions import ConfigurationError


def default_config_dir() -> Path:
    """Resolve the GYB configuration directory (honoring GYB_CONFIG_DIR)."""
    env_override = os.environ.get("GYB_CONFIG_DIR")
    if env_override:
        return Path(env_override).expanduser().resolve()
    return (Path.home() / ".config" / "gyb").resolve()


class ProfileManager:
    """Manages DPoP OAuth and ADC profiles on disk and constructs authorized transports."""

    def __init__(self, config_dir: Path | None = None) -> None:
        self._config_dir = (config_dir or default_config_dir()).resolve()
        self._profiles_dir = self._config_dir / "profiles"
        self._keys_dir = self._config_dir / "keys"

    @property
    def config_dir(self) -> Path:
        return self._config_dir

    @property
    def profiles_dir(self) -> Path:
        return self._profiles_dir

    @property
    def keys_dir(self) -> Path:
        return self._keys_dir

    def _profile_path(self, name: str) -> Path:
        clean = name.strip()
        if not clean or "/" in clean or "\\" in clean or clean in {".", ".."}:
            raise ConfigurationError(f"Invalid profile name: {name!r}")
        return self._profiles_dir / f"{clean}.json"

    def save_profile(self, profile: AuthProfile) -> Path:
        """Persist an OAuth or ADC profile JSON file with 0600 permissions."""
        path = self._profile_path(profile.name)
        self._profiles_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(json.dumps(profile.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        if os.name != "nt":
            os.chmod(path, 0o600)
        return path

    def get_profile(self, name: str) -> AuthProfile:
        """Load a named profile from disk."""
        path = self._profile_path(name)
        if not path.is_file():
            raise ConfigurationError(f"Authentication profile {name!r} does not exist.")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigurationError(f"Corrupt profile JSON in {path}: {exc}") from exc
        return profile_from_dict(raw)

    def list_profiles(self) -> list[AuthProfile]:
        """List all configured profiles sorted by name."""
        if not self._profiles_dir.is_dir():
            return []
        profiles: list[AuthProfile] = []
        for path in sorted(self._profiles_dir.glob("*.json")):
            raw = json.loads(path.read_text(encoding="utf-8"))
            profiles.append(profile_from_dict(raw))
        return profiles

    def delete_profile(self, name: str) -> None:
        """Delete a named profile."""
        path = self._profile_path(name)
        if not path.is_file():
            raise ConfigurationError(f"Authentication profile {name!r} does not exist.")
        path.unlink()

    def setup_oauth_profile(
        self,
        name: str,
        client_secrets_file: Path,
        *,
        signer_config: SignerConfig | None = None,
        scopes: Sequence[str] = DEFAULT_OAUTH_SCOPES,
        email: str | None = None,
        open_browser: bool = True,
        yubikey_pin: str | None = None,
    ) -> OAuthProfile:
        """Run interactive DPoP OAuth flow and save the resulting profile."""
        cfg = signer_config or SignerConfig(key_id=name)
        if cfg.key_id is None:
            cfg.key_id = name
        signer = build_dpop_signer(cfg, keys_dir=self._keys_dir, yubikey_pin=yubikey_pin)
        creds = run_dpop_oauth_flow(
            client_secrets_file,
            signer,
            scopes=scopes,
            login_hint=email,
            open_browser=open_browser,
        )
        profile = OAuthProfile(
            name=name,
            email=email,
            scopes=tuple(scopes),
            signer=cfg,
            authorized_user_info=serialize_dpop_credentials(creds),
        )
        self.save_profile(profile)
        return profile

    def setup_adc_profile(
        self,
        name: str,
        *,
        subject: str | None = None,
        scopes: Sequence[str] = DEFAULT_OAUTH_SCOPES,
        signer_config: SignerConfig | None = None,
        yubikey_pin: str | None = None,
    ) -> ADCProfile:
        """Configure and save an Application Default Credentials profile."""
        if signer_config is not None:
            if signer_config.key_id is None:
                signer_config.key_id = name
            build_dpop_signer(
                signer_config,
                keys_dir=self._keys_dir,
                yubikey_pin=yubikey_pin,
            )
        profile = ADCProfile(
            name=name,
            scopes=tuple(scopes),
            subject=subject,
            signer=signer_config,
        )
        self.save_profile(profile)
        return profile

    def build_authorized_http(
        self,
        profile_name: str | None = None,
        *,
        subject_override: str | None = None,
        scopes: Sequence[str] = DEFAULT_OAUTH_SCOPES,
        max_streams: int = 64,
        enable_http2: bool = True,
        timeout: float = 60.0,
        yubikey_pin: str | None = None,
    ) -> ModernAuthorizedHttp:
        """Resolve credentials for a profile (or default ADC) and return HTTP/2 transport."""
        profile: AuthProfile
        persist_refresh = False
        if profile_name is not None:
            profile = self.get_profile(profile_name)
            persist_refresh = True
        elif (self._profiles_dir / "default.json").is_file():
            profile = self.get_profile("default")
            persist_refresh = True
        else:
            profile = ADCProfile(
                name="default-adc",
                scopes=tuple(scopes),
                subject=subject_override,
                signer=SignerConfig(key_id="default-adc"),
            )

        if isinstance(profile, OAuthProfile):
            signer = build_dpop_signer(
                profile.signer,
                keys_dir=self._keys_dir,
                yubikey_pin=yubikey_pin,
            )
            oauth_creds = load_dpop_oauth_credentials(profile, signer)
            oauth_profile = profile

            def _on_refresh(refreshed: google.auth.credentials.Credentials) -> None:
                if persist_refresh and isinstance(refreshed, DPoPCredentials):
                    oauth_profile.authorized_user_info = serialize_dpop_credentials(refreshed)
                    self.save_profile(oauth_profile)

            return ModernAuthorizedHttp(
                oauth_creds,
                max_streams=max_streams,
                enable_http2=enable_http2,
                timeout=timeout,
                on_credentials_refreshed=_on_refresh,
            )

        adc_signer = (
            build_dpop_signer(
                profile.signer,
                keys_dir=self._keys_dir,
                yubikey_pin=yubikey_pin,
            )
            if profile.signer is not None
            else None
        )
        adc_creds = load_adc_credentials(
            profile,
            signer=adc_signer,
            subject_override=subject_override,
        )
        return ModernAuthorizedHttp(
            adc_creds,
            max_streams=max_streams,
            enable_http2=enable_http2,
            timeout=timeout,
        )
