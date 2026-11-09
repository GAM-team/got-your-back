"""URI parsing and Source/Sink module construction for the ngyb CLI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ngyb.auth.manager import ProfileManager
from ngyb.auth.oauth import GMAIL_FULL_SCOPE, GMAIL_READONLY_SCOPE, GROUPS_MIGRATION_SCOPE
from ngyb.core.exceptions import ConfigurationError
from ngyb.core.interfaces import Sink, Source
from ngyb.core.models import StreamTuningConfig
from ngyb.modules.gmail import GmailClient, GmailSink, GmailSource
from ngyb.modules.google_groups import GoogleGroupsSink, GroupsMigrationClient
from ngyb.modules.local import MSG_DB_FILENAME, LocalGYBSink, LocalGYBSource
from ngyb.modules.mbox import MboxSource

SUPPORTED_SCHEMES = frozenset({"gmail", "groups", "local", "mbox"})


@dataclass(frozen=True, slots=True)
class EndpointSpec:
    """Normalized transfer endpoint specification."""

    scheme: str
    target: str

    @property
    def uri(self) -> str:
        return f"{self.scheme}://{self.target}"


def parse_endpoint(
    raw: str,
    *,
    for_source: bool,
    default_email_scheme: str | None = None,
) -> EndpointSpec:
    """Parse a URI or shorthand path/email into a canonical EndpointSpec."""
    value = raw.strip()
    if not value:
        raise ConfigurationError("Endpoint cannot be empty.")

    if "://" in value:
        scheme_raw, rest = value.split("://", 1)
        scheme = scheme_raw.lower()
        if scheme == "group":
            scheme = "groups"
        if scheme not in SUPPORTED_SCHEMES:
            raise ConfigurationError(
                f"Unsupported endpoint scheme {scheme_raw!r}; "
                "expected gmail, groups, local, or mbox."
            )
        target = rest.strip()
        if not target:
            raise ConfigurationError(f"Missing target in endpoint URI {value!r}.")
        if scheme in {"local", "mbox"}:
            resolved = str(Path(target).expanduser().resolve())
            return EndpointSpec(scheme=scheme, target=resolved)
        return EndpointSpec(scheme=scheme, target=target)

    path_candidate = Path(value).expanduser()
    if default_email_scheme and "@" in value and not path_candidate.exists():
        return EndpointSpec(scheme=default_email_scheme, target=value)

    resolved_path = path_candidate.resolve()
    if resolved_path.suffix.lower() in {".mbox", ".mbx"}:
        return EndpointSpec(scheme="mbox", target=str(resolved_path))

    if (
        for_source
        and resolved_path.is_dir()
        and not (resolved_path / MSG_DB_FILENAME).is_file()
        and any(
            p.suffix.lower() in {".mbox", ".mbx"} for p in resolved_path.rglob("*") if p.is_file()
        )
    ):
        return EndpointSpec(scheme="mbox", target=str(resolved_path))

    return EndpointSpec(scheme="local", target=str(resolved_path))


def build_source_from_spec(
    spec: EndpointSpec,
    *,
    profile_manager: ProfileManager,
    profile_name: str | None,
    subject: str | None,
    tuning: StreamTuningConfig,
    include_spam_trash: bool = False,
    yubikey_pin: str | None = None,
) -> Source:
    """Instantiate a Source module matching ``spec``."""
    if spec.scheme == "local":
        return LocalGYBSource(Path(spec.target))
    if spec.scheme == "mbox":
        return MboxSource(Path(spec.target))
    if spec.scheme == "gmail":
        eff_subject = (
            subject if subject is not None else (spec.target if profile_name is None else None)
        )
        transport = profile_manager.build_authorized_http(
            profile_name,
            subject_override=eff_subject,
            scopes=(GMAIL_READONLY_SCOPE, "email"),
            max_streams=tuning.max_streams,
            enable_http2=tuning.enable_http2,
            yubikey_pin=yubikey_pin,
        )
        return GmailSource(
            GmailClient(transport, user_id=spec.target),
            include_spam_trash=include_spam_trash,
        )
    raise ConfigurationError(f"Endpoint {spec.uri!r} cannot be used as a mail Source.")


def build_sink_from_spec(
    spec: EndpointSpec,
    *,
    profile_manager: ProfileManager,
    profile_name: str | None,
    subject: str | None,
    tuning: StreamTuningConfig,
    email_hint: str = "local-archive",
    strip_labels: bool = False,
    label_prefix: str | None = None,
    label_restored: str | None = None,
    cleanup: bool = False,
    cleanup_from: str | None = None,
    use_insert: bool = False,
    preserve_threads: bool = False,
    yubikey_pin: str | None = None,
) -> Sink:
    """Instantiate a Sink module matching ``spec``."""
    if spec.scheme == "local":
        return LocalGYBSink(Path(spec.target), email_address=email_hint)
    if spec.scheme == "gmail":
        eff_subject = (
            subject if subject is not None else (spec.target if profile_name is None else None)
        )
        transport = profile_manager.build_authorized_http(
            profile_name,
            subject_override=eff_subject,
            scopes=(GMAIL_FULL_SCOPE, "email"),
            max_streams=tuning.max_streams,
            enable_http2=tuning.enable_http2,
            yubikey_pin=yubikey_pin,
        )
        return GmailSink(
            GmailClient(transport, user_id=spec.target),
            strip_labels=strip_labels,
            label_prefix=label_prefix,
            label_restored=label_restored,
            cleanup=cleanup,
            cleanup_from=cleanup_from,
            use_insert=use_insert,
            preserve_threads=preserve_threads,
        )
    if spec.scheme == "groups":
        transport = profile_manager.build_authorized_http(
            profile_name,
            subject_override=subject,
            scopes=(GROUPS_MIGRATION_SCOPE, "email"),
            max_streams=tuning.max_streams,
            enable_http2=tuning.enable_http2,
            yubikey_pin=yubikey_pin,
        )
        return GoogleGroupsSink(
            GroupsMigrationClient(transport, group_email=spec.target),
            cleanup=cleanup,
            cleanup_from=cleanup_from,
        )
    raise ConfigurationError(f"Endpoint {spec.uri!r} cannot be used as a mail Sink.")
