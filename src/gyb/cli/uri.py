"""URI parsing and Source/Sink module construction for the GYB CLI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from gyb.auth.manager import ProfileManager
from gyb.auth.oauth import GMAIL_FULL_SCOPE, GMAIL_READONLY_SCOPE, GROUPS_MIGRATION_SCOPE
from gyb.cli.options import TransferOptions
from gyb.core.exceptions import ConfigurationError
from gyb.core.interfaces import Sink, Source
from gyb.core.models import StreamTuningConfig
from gyb.modules.gmail import GmailClient, GmailSink, GmailSource
from gyb.modules.google_groups import GoogleGroupsSink, GroupsMigrationClient
from gyb.modules.local import MSG_DB_FILENAME, LocalGYBSink, LocalGYBSource
from gyb.modules.mbox import MboxSource

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
    options: TransferOptions,
    tuning: StreamTuningConfig,
    yubikey_pin: str | None = None,
) -> Source:
    """Instantiate a Source module matching ``spec``."""
    if spec.scheme == "local":
        return LocalGYBSource(Path(spec.target))
    if spec.scheme == "mbox":
        return MboxSource(Path(spec.target))
    if spec.scheme == "gmail":
        eff_subject = (
            options.source_subject
            if options.source_subject is not None
            else (spec.target if options.source_profile is None else None)
        )
        transport = profile_manager.build_authorized_http(
            options.source_profile,
            subject_override=eff_subject,
            scopes=(GMAIL_READONLY_SCOPE, "email"),
            max_streams=tuning.max_streams,
            enable_http2=tuning.enable_http2,
            yubikey_pin=yubikey_pin,
        )
        return GmailSource(
            GmailClient(transport, user_id=spec.target),
            include_spam_trash=options.include_spam_trash,
        )
    raise ConfigurationError(f"Endpoint {spec.uri!r} cannot be used as a mail Source.")


def build_sink_from_spec(
    spec: EndpointSpec,
    *,
    profile_manager: ProfileManager,
    options: TransferOptions,
    tuning: StreamTuningConfig,
    email_hint: str = "local-archive",
    yubikey_pin: str | None = None,
) -> Sink:
    """Instantiate a Sink module matching ``spec``."""
    if spec.scheme == "local":
        return LocalGYBSink(Path(spec.target), email_address=email_hint)
    if spec.scheme == "gmail":
        eff_subject = (
            options.dest_subject
            if options.dest_subject is not None
            else (spec.target if options.dest_profile is None else None)
        )
        transport = profile_manager.build_authorized_http(
            options.dest_profile,
            subject_override=eff_subject,
            scopes=(GMAIL_FULL_SCOPE, "email"),
            max_streams=tuning.max_streams,
            enable_http2=tuning.enable_http2,
            yubikey_pin=yubikey_pin,
        )
        return GmailSink(
            GmailClient(transport, user_id=spec.target),
            strip_labels=options.strip_labels,
            label_prefix=options.label_prefix,
            label_restored=options.label_restored,
            cleanup=options.cleanup,
            cleanup_from=options.cleanup_from,
            use_insert=options.use_insert,
            preserve_threads=options.preserve_threads,
        )
    if spec.scheme == "groups":
        transport = profile_manager.build_authorized_http(
            options.dest_profile,
            subject_override=options.dest_subject,
            scopes=(GROUPS_MIGRATION_SCOPE, "email"),
            max_streams=tuning.max_streams,
            enable_http2=tuning.enable_http2,
            yubikey_pin=yubikey_pin,
        )
        return GoogleGroupsSink(
            GroupsMigrationClient(transport, group_email=spec.target),
            cleanup=options.cleanup,
            cleanup_from=options.cleanup_from,
        )
    raise ConfigurationError(f"Endpoint {spec.uri!r} cannot be used as a mail Sink.")
