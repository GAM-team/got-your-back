"""CLI context, transfer option models, and shared Click HTTP/2 tuning decorators."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar, cast

import click
from rich.console import Console

from gyb.auth.manager import ProfileManager
from gyb.core.exceptions import ConfigurationError
from gyb.core.models import StreamTuningConfig
from gyb.db.job_store import JobStore

F = TypeVar("F", bound=Callable[..., Any])


@dataclass(slots=True)
class CLIContext:
    """Shared CLI runtime configuration."""

    config_dir: Path
    console: Console

    def profile_manager(self) -> ProfileManager:
        return ProfileManager(self.config_dir)

    def job_store(self) -> JobStore:
        return JobStore(self.config_dir / "jobs.db")


pass_ctx = click.make_pass_decorator(CLIContext)


@dataclass(frozen=True, slots=True)
class TransferOptions:
    """Typed per-job transfer options persisted in SQLite for 'gyb retry'."""

    source_profile: str | None = None
    dest_profile: str | None = None
    source_subject: str | None = None
    dest_subject: str | None = None
    include_spam_trash: bool = False
    strip_labels: bool = False
    label_prefix: str | None = None
    label_restored: str | None = None
    cleanup: bool = False
    cleanup_from: str | None = None
    use_insert: bool = False
    preserve_threads: bool = False
    no_resume: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize transfer options for JobStore persistence."""
        return {
            "source_profile": self.source_profile,
            "dest_profile": self.dest_profile,
            "source_subject": self.source_subject,
            "dest_subject": self.dest_subject,
            "include_spam_trash": self.include_spam_trash,
            "strip_labels": self.strip_labels,
            "label_prefix": self.label_prefix,
            "label_restored": self.label_restored,
            "cleanup": self.cleanup,
            "cleanup_from": self.cleanup_from,
            "use_insert": self.use_insert,
            "preserve_threads": self.preserve_threads,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TransferOptions:
        """Rehydrate TransferOptions from persisted JobStore JSON."""
        return cls(
            source_profile=data.get("source_profile"),
            dest_profile=data.get("dest_profile"),
            source_subject=data.get("source_subject"),
            dest_subject=data.get("dest_subject"),
            include_spam_trash=bool(data.get("include_spam_trash", False)),
            strip_labels=bool(data.get("strip_labels", False)),
            label_prefix=data.get("label_prefix"),
            label_restored=data.get("label_restored"),
            cleanup=bool(data.get("cleanup", False)),
            cleanup_from=data.get("cleanup_from"),
            use_insert=bool(data.get("use_insert", False)),
            preserve_threads=bool(data.get("preserve_threads", False)),
        )


def stream_tuning_options(func: F) -> F:
    """Attach user-tunable HTTP/2 AIMD stream scaling flags to a Click command."""
    wrapped: Any = func
    options = [
        click.option(
            "--initial-streams",
            type=int,
            default=8,
            show_default=True,
            help="Initial concurrent HTTP/2 streams before slow-start ramp.",
        ),
        click.option(
            "--min-streams",
            type=int,
            default=1,
            show_default=True,
            help="Minimum concurrent streams under heavy server throttling.",
        ),
        click.option(
            "--max-streams",
            type=int,
            default=64,
            show_default=True,
            help="Maximum concurrent HTTP/2 streams.",
        ),
        click.option(
            "--ramp-step",
            type=int,
            default=4,
            show_default=True,
            help="Additive stream step per clean window in congestion avoidance.",
        ),
        click.option(
            "--ramp-interval",
            type=float,
            default=2.0,
            show_default=True,
            help="Seconds per throughput evaluation window.",
        ),
        click.option(
            "--backoff-decrease",
            type=float,
            default=0.5,
            show_default=True,
            help="Multiplicative stream decrease factor (0..1) on 429/503 throttle.",
        ),
        click.option(
            "--base-backoff",
            type=float,
            default=1.0,
            show_default=True,
            help="Base pause seconds for global exponential backoff.",
        ),
        click.option(
            "--max-backoff",
            type=float,
            default=60.0,
            show_default=True,
            help="Maximum global backoff pause seconds.",
        ),
        click.option(
            "--disable-http2",
            is_flag=True,
            default=False,
            help="Force HTTP/1.1 transport instead of HTTP/2 stream multiplexing.",
        ),
    ]
    for opt in reversed(options):
        wrapped = opt(wrapped)
    return cast(F, wrapped)


def build_tuning_from_kwargs(kwargs: dict[str, Any]) -> StreamTuningConfig:
    """Pop stream tuning options from Click kwargs and validate StreamTuningConfig."""
    try:
        return StreamTuningConfig(
            initial_streams=int(kwargs.pop("initial_streams", 8)),
            min_streams=int(kwargs.pop("min_streams", 1)),
            max_streams=int(kwargs.pop("max_streams", 64)),
            ramp_step=int(kwargs.pop("ramp_step", 4)),
            ramp_interval=float(kwargs.pop("ramp_interval", 2.0)),
            backoff_decrease_factor=float(kwargs.pop("backoff_decrease", 0.5)),
            base_backoff=float(kwargs.pop("base_backoff", 1.0)),
            max_backoff=float(kwargs.pop("max_backoff", 60.0)),
            enable_http2=not bool(kwargs.pop("disable_http2", False)),
        )
    except ValueError as exc:
        raise ConfigurationError(str(exc)) from exc
