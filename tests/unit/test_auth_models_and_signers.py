"""Unit tests for auth models, OS-scoped DPoP signers, and ThreadSafeDPoPSigner."""

from __future__ import annotations

import builtins
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from google.auth.dpop import DPoPSigner, SoftwareDPoPSigner

from gyb.auth import (
    ADCProfile,
    OAuthProfile,
    ProfileKind,
    SignerConfig,
    SignerType,
    ThreadSafeDPoPSigner,
    available_signer_types,
    build_dpop_signer,
    ensure_software_pem_key,
    profile_from_dict,
)
from gyb.auth.signers import DEFAULT_MACOS_SE_LABEL
from gyb.core.exceptions import AuthenticationError, ConfigurationError


class DummyHardwareSigner(DPoPSigner):
    def __init__(self, key_id: str | None = "hw-1", **kwargs: Any) -> None:
        self._soft = SoftwareDPoPSigner(ec.generate_private_key(ec.SECP256R1()), key_id=key_id)
        self.init_kwargs = kwargs

    @property
    def algorithm(self) -> str:
        return str(self._soft.algorithm)

    @property
    def public_jwk(self) -> dict[str, Any]:
        return dict(self._soft.public_jwk)

    @property
    def key_id(self) -> str | None:
        kid = self._soft.key_id
        return str(kid) if kid is not None else None

    def sign(self, data: bytes) -> bytes:
        return bytes(self._soft.sign(data))

    def to_dict(self) -> dict[str, Any]:
        return {"credential_id": "cred-1", "rp_id": "google.com"}


def test_auth_models_round_trip_and_errors() -> None:
    assert DEFAULT_MACOS_SE_LABEL == "gyb-dpop-signing"
    cfg = SignerConfig(
        signer_type=SignerType.YUBIKEY,
        key_id="yk1",
        piv_slot="9c",
        yubikey_serial=123456,
        tpm_handle=0x81000001,
        fido2_credential_data={"rp_id": "example.com"},
        dpop_thumbprint="jkt-123",
    )
    restored_cfg = SignerConfig.from_dict(cfg.to_dict())
    assert restored_cfg == cfg

    with pytest.raises(ConfigurationError, match="Invalid signer_type"):
        SignerConfig.from_dict({"signer_type": "bogus"})

    oauth_prof = OAuthProfile(
        name="work",
        email="alice@example.com",
        scopes=("email",),
        signer=SignerConfig(key_id="work"),
        authorized_user_info={"refresh_token": "r1"},
    )
    parsed_oauth = profile_from_dict(oauth_prof.to_dict())
    assert isinstance(parsed_oauth, OAuthProfile)
    assert parsed_oauth.kind == ProfileKind.OAUTH
    assert parsed_oauth.email == "alice@example.com"

    with pytest.raises(ConfigurationError, match="Malformed OAuth profile"):
        OAuthProfile.from_dict({"name": "broken"})

    adc_prof = ADCProfile(
        name="sa-dwd",
        scopes=("https://mail.google.com/",),
        subject="bob@example.com",
        signer=SignerConfig(key_id="sa-dwd"),
    )
    parsed_adc = profile_from_dict(adc_prof.to_dict())
    assert isinstance(parsed_adc, ADCProfile)
    assert parsed_adc.subject == "bob@example.com"
    assert parsed_adc.signer is not None

    minimal_adc = ADCProfile(name="sa-plain", scopes=("email",))
    parsed_min_adc = ADCProfile.from_dict(minimal_adc.to_dict())
    assert parsed_min_adc.subject is None
    assert parsed_min_adc.signer is None

    with pytest.raises(ConfigurationError, match="Malformed ADC profile"):
        ADCProfile.from_dict({})

    with pytest.raises(ConfigurationError, match="Unknown authentication profile kind"):
        profile_from_dict({"kind": "saml"})


def test_available_signer_types_by_platform() -> None:
    mac = available_signer_types("darwin")
    assert SignerType.MACOS_SE in mac
    assert SignerType.WINDOWS_TPM not in mac
    assert SignerType.LINUX_TPM not in mac

    win = available_signer_types("win32")
    assert SignerType.WINDOWS_TPM in win
    assert SignerType.MACOS_SE not in win
    assert SignerType.LINUX_TPM not in win

    lin = available_signer_types("linux")
    assert SignerType.LINUX_TPM in lin
    assert SignerType.MACOS_SE not in lin
    assert SignerType.WINDOWS_TPM not in lin

    bsd = available_signer_types("freebsd14")
    assert set(bsd) == {
        SignerType.SOFTWARE,
        SignerType.ECP,
        SignerType.YUBIKEY,
        SignerType.FIDO2,
    }


def test_software_pem_generation_and_thread_safe_signer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pem_file = tmp_path / "keys" / "test.pem"
    pem1 = ensure_software_pem_key(pem_file)
    pem2 = ensure_software_pem_key(pem_file)
    assert pem1 == pem2
    if os.name != "nt":
        assert (pem_file.stat().st_mode & 0o777) == 0o600

    chmod_calls: list[tuple[str, int]] = []
    monkeypatch.setattr("gyb.auth.signers.os.name", "posix")
    monkeypatch.setattr(
        "gyb.auth.signers.os.chmod",
        lambda p, m: chmod_calls.append((str(p), m)),
    )
    posix_pem = tmp_path / "keys" / "posix.pem"
    assert ensure_software_pem_key(posix_pem).startswith(b"-----BEGIN PRIVATE KEY-----")
    assert chmod_calls == [(str(posix_pem), 0o600)]

    monkeypatch.setattr("gyb.auth.signers.os.name", "nt")
    nt_pem = tmp_path / "keys" / "nt.pem"
    assert ensure_software_pem_key(nt_pem).startswith(b"-----BEGIN PRIVATE KEY-----")
    assert len(chmod_calls) == 1
    monkeypatch.undo()

    cfg = SignerConfig(signer_type=SignerType.SOFTWARE, key_id="prof1")
    signer = build_dpop_signer(cfg, keys_dir=tmp_path / "keys", platform="darwin")
    assert isinstance(signer, ThreadSafeDPoPSigner)
    assert isinstance(signer.inner, SoftwareDPoPSigner)
    assert signer.algorithm == "ES256"
    assert signer.key_id == "prof1"
    assert signer.public_jwk["crv"] == "P-256"
    assert cfg.dpop_thumbprint == signer.thumbprint
    proof = signer.create_proof("POST", "https://oauth2.googleapis.com/token")
    assert len(proof.split(".")) == 3

    # None key_id branch on ThreadSafeDPoPSigner
    nokid = build_dpop_signer(
        SignerConfig(signer_type=SignerType.SOFTWARE, key_id=None),
        keys_dir=tmp_path / "keys",
        platform="darwin",
    )
    assert nokid.key_id is None

    signer_reloaded = build_dpop_signer(cfg, keys_dir=tmp_path / "keys", platform="darwin")
    assert signer_reloaded.thumbprint == signer.thumbprint

    bad_cfg = SignerConfig(
        signer_type=SignerType.SOFTWARE,
        pem_path=cfg.pem_path,
        dpop_thumbprint="wrong-thumbprint",
    )
    with pytest.raises(AuthenticationError, match="thumbprint mismatch"):
        build_dpop_signer(bad_cfg, keys_dir=tmp_path / "keys", platform="darwin")


def test_all_hardware_signer_builders_and_platform_guards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(AuthenticationError, match="not supported on platform"):
        build_dpop_signer(
            SignerConfig(signer_type=SignerType.WINDOWS_TPM),
            keys_dir=tmp_path,
            platform="darwin",
        )

    fake_modules: dict[str, Any] = {
        "dpop_signer_macos_secureenclave": SimpleNamespace(
            SecureEnclaveDPoPSigner=DummyHardwareSigner
        ),
        "dpop_signer_windows_tpm": SimpleNamespace(WindowsCNGDPoPSigner=DummyHardwareSigner),
        "dpop_signer_linux_tpm": SimpleNamespace(LinuxTPMDPoPSigner=DummyHardwareSigner),
        "dpop_signer_ecp": SimpleNamespace(ECPDPoPSigner=DummyHardwareSigner),
        "dpop_signer_yubikey": SimpleNamespace(YubiKeyDPoPSigner=DummyHardwareSigner),
        "dpop_signer_fido2_previewsign": SimpleNamespace(
            Fido2PreviewSignDPoPSigner=SimpleNamespace(
                from_dict=lambda data: DummyHardwareSigner(key_id="fido-loaded", data=data)
            ),
            generate_signing_credential=lambda key_id=None: DummyHardwareSigner(key_id=key_id),
        ),
    }
    monkeypatch.setattr(
        "gyb.auth.signers.importlib.import_module",
        lambda name: fake_modules[name],
    )

    se = build_dpop_signer(
        SignerConfig(signer_type=SignerType.MACOS_SE),
        keys_dir=tmp_path,
        platform="darwin",
    )
    assert se.thumbprint

    wtpm = build_dpop_signer(
        SignerConfig(signer_type=SignerType.WINDOWS_TPM, subject="CN=Alice"),
        keys_dir=tmp_path,
        platform="win32",
    )
    assert wtpm.thumbprint

    ltpm = build_dpop_signer(
        SignerConfig(signer_type=SignerType.LINUX_TPM),
        keys_dir=tmp_path,
        platform="linux",
    )
    assert ltpm.thumbprint

    ecp = build_dpop_signer(
        SignerConfig(signer_type=SignerType.ECP, ecp_config_path="/etc/ecp.json"),
        keys_dir=tmp_path,
        platform="linux",
    )
    assert ecp.thumbprint

    yk = build_dpop_signer(
        SignerConfig(signer_type=SignerType.YUBIKEY, yubikey_serial=42),
        keys_dir=tmp_path,
        yubikey_pin="123456",
        platform="darwin",
    )
    assert yk.thumbprint

    fido_gen_cfg = SignerConfig(signer_type=SignerType.FIDO2, key_id="fido-new")
    fido_gen = build_dpop_signer(fido_gen_cfg, keys_dir=tmp_path, platform="darwin")
    assert fido_gen.thumbprint
    assert fido_gen_cfg.fido2_credential_data == {"credential_id": "cred-1", "rp_id": "google.com"}

    fido_load_cfg = SignerConfig(
        signer_type=SignerType.FIDO2,
        fido2_credential_data={"credential_id": "cred-1"},
    )
    fido_loaded = build_dpop_signer(fido_load_cfg, keys_dir=tmp_path, platform="darwin")
    assert fido_loaded.key_id == "fido-loaded"

    def _boom(**_: Any) -> Any:
        raise RuntimeError("TPM device busy")

    fake_modules["dpop_signer_linux_tpm"] = SimpleNamespace(LinuxTPMDPoPSigner=_boom)
    with pytest.raises(AuthenticationError, match="Failed to initialize linux-tpm"):
        build_dpop_signer(
            SignerConfig(signer_type=SignerType.LINUX_TPM),
            keys_dir=tmp_path,
            platform="linux",
        )

    orig_import = builtins.__import__
    monkeypatch.undo()
    monkeypatch.setattr(
        "gyb.auth.signers.importlib.import_module",
        lambda name: (_ for _ in ()).throw(ImportError(f"No module named {name}")),
    )
    _ = orig_import
    with pytest.raises(AuthenticationError, match="not installed"):
        build_dpop_signer(
            SignerConfig(signer_type=SignerType.ECP),
            keys_dir=tmp_path,
            platform="darwin",
        )
