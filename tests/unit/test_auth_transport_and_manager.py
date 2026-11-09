"""Unit tests for ModernAuthorizedHttp, DPoP OAuth flow, ADC, and ProfileManager."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import google.auth.credentials
import google.auth.exceptions
import google.oauth2.credentials
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from google.auth.dpop import SoftwareDPoPSigner
from google.oauth2.dpop_credentials import DPoPCredentials

from ngyb.auth import (
    ADCProfile,
    ModernAuthorizedHttp,
    OAuthProfile,
    ProfileManager,
    SignerConfig,
    compute_pool_maxsize,
    default_config_dir,
    load_adc_credentials,
    load_dpop_oauth_credentials,
    run_dpop_oauth_flow,
    serialize_dpop_credentials,
)
from ngyb.core.exceptions import AuthenticationError, ConfigurationError


def _make_dpop_creds(
    signer: SoftwareDPoPSigner | None = None,
    *,
    expired: bool = False,
) -> tuple[DPoPCredentials, SoftwareDPoPSigner]:
    sig = signer or SoftwareDPoPSigner(ec.generate_private_key(ec.SECP256R1()), key_id="k1")
    creds = DPoPCredentials(
        token="tok-initial",
        dpop_signer=sig,
        dpop_nonce="nonce-1",
        refresh_token="ref-1",
        token_uri="https://oauth2.googleapis.com/token",
        client_id="cid",
        client_secret="csec",
        scopes=["email"],
    )
    creds.expiry = (
        datetime.now(tz=UTC).replace(tzinfo=None) - timedelta(minutes=10)
        if expired
        else datetime.now(tz=UTC).replace(tzinfo=None) + timedelta(hours=1)
    )
    return creds, sig


class FakeHttpPool:
    def __init__(self, responses: list[tuple[int, bytes | str]]) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[str, str, dict[str, str]]] = []
        self.closed = False

    def request(
        self,
        uri: str,
        method: str = "GET",
        body: bytes | str | None = None,
        headers: dict[str, str] | None = None,
        **_: Any,
    ) -> tuple[Any, bytes | str]:
        _ = body
        self.calls.append((method, uri, dict(headers or {})))
        status, payload = self._responses.pop(0)
        return SimpleNamespace(status=status, version=20), payload

    def close(self) -> None:
        self.closed = True


def test_modern_authorized_http_refresh_401_and_dpop_headers() -> None:
    assert compute_pool_maxsize(32) == 16
    assert compute_pool_maxsize(200) == 16
    assert compute_pool_maxsize(900) == 20

    creds, _ = _make_dpop_creds(expired=True)
    refresh_calls = 0

    def _fake_refresh(request: Any) -> None:
        nonlocal refresh_calls
        _ = request
        refresh_calls += 1
        creds.token = f"tok-refreshed-{refresh_calls}"
        creds.expiry = datetime.now(tz=UTC).replace(tzinfo=None) + timedelta(hours=1)

    creds.refresh = _fake_refresh  # type: ignore[method-assign]
    refreshed_seen: list[str] = []

    http_pool = FakeHttpPool([(401, b"unauth"), (200, "ok-str")])
    refresh_pool = FakeHttpPool([])
    transport = ModernAuthorizedHttp(
        creds,
        http=http_pool,
        refresh_http=refresh_pool,
        on_credentials_refreshed=lambda c: refreshed_seen.append(str(c.token)),
    )
    assert transport.credentials is creds
    assert transport.http is http_pool
    assert transport.auth_request is not None

    resp, content = transport.request(
        "https://gmail.googleapis.com/gmail/v1/users/me/profile",
        headers={"Accept": "application/json"},
    )
    assert resp.status == 200
    assert content == b"ok-str"
    # Expired initial refresh + forced 401 refresh = 2 refreshes
    assert refresh_calls == 2
    assert refreshed_seen == ["tok-refreshed-1", "tok-refreshed-2"]
    # Verify both Authorization and DPoP proof headers were attached!
    sent_headers = {k.lower(): v for k, v in http_pool.calls[-1][2].items()}
    assert sent_headers["authorization"] == "Bearer tok-refreshed-2"
    assert "dpop" in sent_headers

    # Subsequent request when token is already valid & 200 bytes response (no refresh, no 401)
    http_pool_ok = FakeHttpPool([(200, b"ok-bytes")])
    transport_no_cb = ModernAuthorizedHttp(creds, http=http_pool_ok, refresh_http=refresh_pool)
    resp2, content2 = transport_no_cb.request(
        "https://gmail.googleapis.com/gmail/v1/users/me/profile"
    )
    assert resp2.status == 200
    assert content2 == b"ok-bytes"
    assert refresh_calls == 2
    # Forced refresh when on_credentials_refreshed is None
    transport_no_cb.ensure_valid_token(force=True)
    assert refresh_calls == 3

    transport.close()
    assert http_pool.closed and refresh_pool.closed

    # Default modern_httplib2.Http instantiation and RefreshError wrapping
    fail_creds, _ = _make_dpop_creds(expired=True)

    def _fail_refresh(_: Any) -> None:
        raise google.auth.exceptions.RefreshError("invalid_grant")

    fail_creds.refresh = _fail_refresh  # type: ignore[method-assign]
    default_transport = ModernAuthorizedHttp(fail_creds, max_streams=16, enable_http2=True)
    try:
        with pytest.raises(AuthenticationError, match="Credential refresh failed"):
            default_transport.ensure_valid_token()
    finally:
        default_transport.close()


def test_oauth_flow_and_serialization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    creds, signer = _make_dpop_creds()
    missing_file = tmp_path / "missing.json"
    with pytest.raises(AuthenticationError, match="Client secrets file not found"):
        run_dpop_oauth_flow(missing_file, signer)

    secrets_file = tmp_path / "client_secrets.json"
    secrets_file.write_text('{"installed": {"client_id": "c", "client_secret": "s"}}')

    captured_kwargs: dict[str, Any] = {}

    class FakeFlow:
        def run_local_server(self, **kwargs: Any) -> Any:
            captured_kwargs.update(kwargs)
            return creds

    monkeypatch.setattr(
        "ngyb.auth.oauth.InstalledAppFlow.from_client_secrets_file",
        lambda path, scopes, dpop_signer: FakeFlow(),
    )
    out = run_dpop_oauth_flow(secrets_file, signer, login_hint="u@example.com", open_browser=False)
    assert out is creds
    assert captured_kwargs["login_hint"] == "u@example.com"

    # Without login_hint
    captured_kwargs.clear()
    run_dpop_oauth_flow(secrets_file, signer, open_browser=False)
    assert "login_hint" not in captured_kwargs

    # Non-DPoPCredentials return value rejected
    class UnboundFlow:
        def run_local_server(self, **_: Any) -> Any:
            return SimpleNamespace(token="unbound")

    monkeypatch.setattr(
        "ngyb.auth.oauth.InstalledAppFlow.from_client_secrets_file",
        lambda path, scopes, dpop_signer: UnboundFlow(),
    )
    with pytest.raises(AuthenticationError, match="unbound OAuth tokens are forbidden"):
        run_dpop_oauth_flow(secrets_file, signer)

    # Flow exception wrapped
    monkeypatch.setattr(
        "ngyb.auth.oauth.InstalledAppFlow.from_client_secrets_file",
        lambda *a, **kw: (_ for _ in ()).throw(ValueError("bad client json")),
    )
    with pytest.raises(AuthenticationError, match="authorization flow failed"):
        run_dpop_oauth_flow(secrets_file, signer)

    # Serialization requires bound signer
    unbound_dpop = DPoPCredentials(token="x", dpop_signer=None)
    with pytest.raises(AuthenticationError, match="without a bound DPoPSigner"):
        serialize_dpop_credentials(unbound_dpop)

    serialized = serialize_dpop_credentials(creds)
    assert serialized["dpop_thumbprint"] == signer.thumbprint

    prof = OAuthProfile(
        name="p1",
        scopes=("email",),
        signer=SignerConfig(key_id="k1", dpop_thumbprint=signer.thumbprint),
        authorized_user_info=serialized,
    )
    rehydrated = load_dpop_oauth_credentials(prof, signer)
    assert rehydrated.dpop_signer is signer

    other_signer = SoftwareDPoPSigner(ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(AuthenticationError, match="Invalid or mismatched DPoP"):
        load_dpop_oauth_credentials(prof, other_signer)


def test_adc_loader_cases(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = ADCProfile(name="adc1", scopes=("email",), subject="user@example.com")

    # DefaultCredentialsError
    monkeypatch.setattr(
        "ngyb.auth.adc.google.auth.default",
        lambda scopes: (_ for _ in ()).throw(
            google.auth.exceptions.DefaultCredentialsError("no adc")
        ),
    )
    with pytest.raises(AuthenticationError, match="Unable to load Application Default"):
        load_adc_credentials(profile)

    # Service account supporting with_subject
    class FakeSACreds(google.auth.credentials.Credentials):
        def __init__(self, subject: str | None = None) -> None:
            super().__init__()
            self.token = "sa-tok"
            self.subject = subject

        def refresh(self, request: Any) -> None:
            _ = request

        def with_subject(self, subject: str) -> FakeSACreds:
            return FakeSACreds(subject=subject)

    monkeypatch.setattr("ngyb.auth.adc.google.auth.default", lambda scopes: (FakeSACreds(), "proj"))
    sa_loaded = load_adc_credentials(profile)
    assert isinstance(sa_loaded, FakeSACreds)
    assert sa_loaded.subject == "user@example.com"

    # Credential without with_subject when subject is requested
    class NonDelegatableCreds(google.auth.credentials.Credentials):
        def refresh(self, request: Any) -> None:
            _ = request

    monkeypatch.setattr(
        "ngyb.auth.adc.google.auth.default", lambda scopes: (NonDelegatableCreds(), "proj")
    )
    with pytest.raises(AuthenticationError, match="does not support Domain-Wide Delegation"):
        load_adc_credentials(profile)

    # End-user OAuth credentials from ADC upgraded to DPoPCredentials
    plain_user_creds = google.oauth2.credentials.Credentials(
        token="u-tok",
        refresh_token="u-ref",
        token_uri="https://oauth2.googleapis.com/token",
        client_id="cid",
        client_secret="csec",
        scopes=["email"],
    )
    monkeypatch.setattr(
        "ngyb.auth.adc.google.auth.default", lambda scopes: (plain_user_creds, "proj")
    )
    no_subj_profile = ADCProfile(name="adc-user", scopes=("email",))
    with pytest.raises(AuthenticationError, match="require a DPoP signer"):
        load_adc_credentials(no_subj_profile, signer=None)

    _, signer = _make_dpop_creds()
    upgraded = load_adc_credentials(no_subj_profile, signer=signer)
    assert isinstance(upgraded, DPoPCredentials)
    assert upgraded.dpop_signer is signer


def test_profile_manager_full_lifecycle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NGYB_CONFIG_DIR", str(tmp_path / "env-cfg"))
    assert default_config_dir() == (tmp_path / "env-cfg").resolve()
    monkeypatch.delenv("NGYB_CONFIG_DIR", raising=False)
    assert default_config_dir().name == "ngyb"

    mgr = ProfileManager(tmp_path / "cfg")
    assert mgr.config_dir == (tmp_path / "cfg").resolve()
    assert mgr.profiles_dir.name == "profiles"
    assert mgr.keys_dir.name == "keys"
    assert mgr.list_profiles() == []

    with pytest.raises(ConfigurationError, match="Invalid profile name"):
        mgr.get_profile("../escape")
    with pytest.raises(ConfigurationError, match="does not exist"):
        mgr.get_profile("nope")
    with pytest.raises(ConfigurationError, match="does not exist"):
        mgr.delete_profile("nope")

    # Explicitly exercise both POSIX (chmod) and Windows (nt) branches on all OSes
    chmod_calls: list[tuple[str, int]] = []
    monkeypatch.setattr("ngyb.auth.manager.os.name", "posix")
    monkeypatch.setattr(
        "ngyb.auth.manager.os.chmod",
        lambda p, m: chmod_calls.append((str(p), m)),
    )
    posix_saved = mgr.save_profile(ADCProfile(name="posix-adc", scopes=("email",)))
    assert chmod_calls == [(str(posix_saved), 0o600)]
    mgr.delete_profile("posix-adc")

    monkeypatch.setattr("ngyb.auth.manager.os.name", "nt")
    mgr.save_profile(ADCProfile(name="win-adc", scopes=("email",)))
    assert len(chmod_calls) == 1
    monkeypatch.undo()
    assert len(mgr.list_profiles()) == 1
    mgr.delete_profile("win-adc")

    # Corrupt JSON detection
    mgr.profiles_dir.mkdir(parents=True, exist_ok=True)
    bad_path = mgr.profiles_dir / "corrupt.json"
    bad_path.write_text("{not-json")
    with pytest.raises(ConfigurationError, match="Corrupt profile JSON"):
        mgr.get_profile("corrupt")
    bad_path.unlink()

    # setup_oauth_profile & build_authorized_http with refresh persistence
    secrets = tmp_path / "secrets.json"
    secrets.write_text("{}")

    def _fake_flow(
        client_secrets_file: Path,
        signer: Any,
        *,
        scopes: Any,
        login_hint: str | None = None,
        open_browser: bool = True,
    ) -> DPoPCredentials:
        _ = (client_secrets_file, scopes, login_hint, open_browser)
        c = DPoPCredentials(
            token="t1",
            dpop_signer=signer,
            dpop_nonce="n1",
            refresh_token="r1",
            token_uri="https://oauth2.googleapis.com/token",
            client_id="cid",
            client_secret="csec",
            scopes=["email"],
        )
        return c

    monkeypatch.setattr("ngyb.auth.manager.run_dpop_oauth_flow", _fake_flow)
    oauth_prof = mgr.setup_oauth_profile(
        "default",
        secrets,
        signer_config=SignerConfig(),
        email="alice@example.com",
        open_browser=False,
    )
    if os.name != "nt":
        assert ((mgr.profiles_dir / "default.json").stat().st_mode & 0o777) == 0o600
    assert oauth_prof.signer.key_id == "default"

    # Build authorized HTTP using implicit 'default' profile and trigger refresh callback
    http_default = mgr.build_authorized_http(None)
    try:
        assert isinstance(http_default.credentials, DPoPCredentials)
        http_default.credentials._dpop_nonce = "rotated-nonce"
        assert http_default._on_refreshed is not None
        http_default._on_refreshed(http_default.credentials)
        # Non-DPoPCredentials passed to _on_refreshed is safely ignored
        http_default._on_refreshed(SimpleNamespace())  # type: ignore[arg-type]
        reloaded = json.loads((mgr.profiles_dir / "default.json").read_text())
        assert reloaded["authorized_user_info"]["dpop_nonce"] == "rotated-nonce"
    finally:
        http_default.close()

    # Named OAuth profile lookup with pre-populated key_id
    mgr.setup_oauth_profile(
        "explicit-key",
        secrets,
        signer_config=SignerConfig(key_id="custom-kid"),
        open_browser=False,
    )
    http_named = mgr.build_authorized_http("explicit-key")
    http_named.close()
    mgr.delete_profile("default")

    # setup_adc_profile (with signer & without signer) + default-adc fallback
    adc_with_signer = mgr.setup_adc_profile("adc-signed", signer_config=SignerConfig())
    assert adc_with_signer.signer is not None and adc_with_signer.signer.key_id == "adc-signed"
    mgr.setup_adc_profile("adc-explicit-kid", signer_config=SignerConfig(key_id="kid2"))
    mgr.setup_adc_profile("adc-nosigner", subject="bob@example.com")

    class DummySA(google.auth.credentials.Credentials):
        def refresh(self, request: Any) -> None:
            _ = request

        def with_subject(self, subject: str) -> DummySA:
            _ = subject
            return self

    monkeypatch.setattr("ngyb.auth.adc.google.auth.default", lambda scopes: (DummySA(), "proj"))
    t1 = mgr.build_authorized_http("adc-nosigner")
    t1.close()
    t2 = mgr.build_authorized_http(None, subject_override="carol@example.com")
    t2.close()
