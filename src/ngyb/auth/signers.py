"""OS-scoped DPoP signer registry, thread-safe wrapper, and key lifecycle helpers."""

from __future__ import annotations

import importlib
import os
import sys
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.auth.dpop import DPoPSigner, SoftwareDPoPSigner

from ngyb.auth.models import SignerConfig, SignerType
from ngyb.core.exceptions import AuthenticationError

DEFAULT_MACOS_SE_LABEL = "ngyb-dpop-signing"
DEFAULT_LINUX_TPM_HANDLE = 0x81000001
DEFAULT_YUBIKEY_SLOT = "9c"


def available_signer_types(platform: str | None = None) -> list[SignerType]:
    """Return DPoP signer types supported on the target operating system."""
    plat = platform if platform is not None else sys.platform
    supported: list[SignerType] = [SignerType.SOFTWARE]
    if plat == "darwin":
        supported.append(SignerType.MACOS_SE)
    elif plat == "win32":
        supported.append(SignerType.WINDOWS_TPM)
    elif plat.startswith("linux"):
        supported.append(SignerType.LINUX_TPM)
    supported.extend([SignerType.ECP, SignerType.YUBIKEY, SignerType.FIDO2])
    return supported


class ThreadSafeDPoPSigner(DPoPSigner):
    """Serializes hardware/software DPoP signing calls across HTTP/2 worker threads."""

    def __init__(self, inner: DPoPSigner) -> None:
        self._inner = inner
        self._lock = threading.RLock()

    @property
    def inner(self) -> DPoPSigner:
        """Wrapped DPoPSigner instance."""
        return self._inner

    @property
    def algorithm(self) -> str:
        return str(self._inner.algorithm)

    @property
    def public_jwk(self) -> Mapping[str, Any]:
        return self._inner.public_jwk

    @property
    def key_id(self) -> str | None:
        return self._inner.key_id

    def sign(self, data: bytes) -> bytes:
        with self._lock:
            return bytes(self._inner.sign(data))


def ensure_software_pem_key(pem_path: Path) -> bytes:
    """Load an existing ECDSA P-256 PEM key or generate a new 0600 key file."""
    if pem_path.exists():
        return pem_path.read_bytes()

    pem_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_key = ec.generate_private_key(ec.SECP256R1())
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_path.write_bytes(pem_bytes)
    if os.name != "nt":
        os.chmod(pem_path, 0o600)
    return pem_bytes


def _import_signer_module(module_name: str) -> Any:
    try:
        return importlib.import_module(module_name)
    except ImportError as exc:
        raise AuthenticationError(
            f"DPoP signer package {module_name!r} is not installed in this environment: {exc}"
        ) from exc


def build_dpop_signer(
    config: SignerConfig,
    *,
    keys_dir: Path,
    yubikey_pin: str | None = None,
    platform: str | None = None,
) -> ThreadSafeDPoPSigner:
    """Instantiate and wrap the configured DPoP signer, enforcing OS isolation."""
    plat = platform if platform is not None else sys.platform
    if config.signer_type not in available_signer_types(plat):
        raise AuthenticationError(
            f"DPoP signer {config.signer_type.value!r} is not supported on platform {plat!r}."
        )

    inner: DPoPSigner
    try:
        if config.signer_type == SignerType.SOFTWARE:
            pem_path = (
                Path(config.pem_path)
                if config.pem_path
                else (keys_dir / f"{config.key_id or 'default'}.pem")
            )
            pem_bytes = ensure_software_pem_key(pem_path)
            config.pem_path = str(pem_path)
            inner = SoftwareDPoPSigner.from_pem(pem_bytes, key_id=config.key_id)
        elif config.signer_type == SignerType.MACOS_SE:
            mod = _import_signer_module("dpop_signer_macos_secureenclave")
            inner = mod.SecureEnclaveDPoPSigner(
                label=config.label or DEFAULT_MACOS_SE_LABEL,
                key_id=config.key_id,
            )
        elif config.signer_type == SignerType.WINDOWS_TPM:
            mod = _import_signer_module("dpop_signer_windows_tpm")
            inner = mod.WindowsCNGDPoPSigner(
                subject=config.subject,
                thumbprint=config.cert_thumbprint,
                key_id=config.key_id,
            )
        elif config.signer_type == SignerType.LINUX_TPM:
            mod = _import_signer_module("dpop_signer_linux_tpm")
            inner = mod.LinuxTPMDPoPSigner(
                handle=config.tpm_handle
                if config.tpm_handle is not None
                else DEFAULT_LINUX_TPM_HANDLE,
                key_id=config.key_id,
            )
        elif config.signer_type == SignerType.ECP:
            mod = _import_signer_module("dpop_signer_ecp")
            inner = mod.ECPDPoPSigner(
                config_path=config.ecp_config_path,
                key_id=config.key_id,
            )
        elif config.signer_type == SignerType.YUBIKEY:
            mod = _import_signer_module("dpop_signer_yubikey")
            inner = mod.YubiKeyDPoPSigner(
                slot=config.piv_slot or DEFAULT_YUBIKEY_SLOT,
                serial=config.yubikey_serial,
                pin=yubikey_pin,
                key_id=config.key_id,
            )
        else:
            # SignerType.FIDO2
            mod = _import_signer_module("dpop_signer_fido2_previewsign")
            if config.fido2_credential_data is not None:
                fido_signer = mod.Fido2PreviewSignDPoPSigner.from_dict(config.fido2_credential_data)
            else:
                fido_signer = mod.generate_signing_credential(key_id=config.key_id)
                config.fido2_credential_data = dict(fido_signer.to_dict())
            inner = fido_signer
    except AuthenticationError:
        raise
    except Exception as exc:
        raise AuthenticationError(
            f"Failed to initialize {config.signer_type.value} DPoP signer: {exc}"
        ) from exc

    actual_thumbprint = inner.thumbprint
    if config.dpop_thumbprint is not None and config.dpop_thumbprint != actual_thumbprint:
        raise AuthenticationError(
            f"DPoP signer thumbprint mismatch: expected {config.dpop_thumbprint}, "
            f"got {actual_thumbprint}"
        )
    config.dpop_thumbprint = actual_thumbprint
    return ThreadSafeDPoPSigner(inner)
