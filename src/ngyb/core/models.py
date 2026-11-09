"""Core data models for messages, transfer results, jobs, and HTTP/2 stream tuning."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from typing import Any


class TransferStatus(StrEnum):
    """Per-message transfer status."""

    PENDING = "pending"
    SUCCESS = "success"
    SKIPPED = "skipped"
    FAILED = "failed"


class JobState(StrEnum):
    """Lifecycle state of a backup, restore, migration, or retry job."""

    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class StreamTuningConfig:
    """User-tunable AIMD HTTP/2 stream concurrency and backoff parameters."""

    initial_streams: int = 8
    min_streams: int = 1
    max_streams: int = 64
    ramp_interval: float = 2.0
    ramp_step: int = 4
    backoff_decrease_factor: float = 0.5
    base_backoff: float = 1.0
    max_backoff: float = 60.0
    jitter_ratio: float = 0.25
    enable_http2: bool = True

    def __post_init__(self) -> None:
        if self.min_streams < 1:
            raise ValueError("min_streams must be >= 1")
        if self.initial_streams < self.min_streams:
            raise ValueError("initial_streams must be >= min_streams")
        if self.max_streams < self.initial_streams:
            raise ValueError("max_streams must be >= initial_streams")
        if self.ramp_step < 1:
            raise ValueError("ramp_step must be >= 1")
        if self.ramp_interval <= 0:
            raise ValueError("ramp_interval must be > 0")
        if not (0.0 < self.backoff_decrease_factor < 1.0):
            raise ValueError("backoff_decrease_factor must be strictly between 0.0 and 1.0")
        if self.base_backoff <= 0:
            raise ValueError("base_backoff must be > 0")
        if self.max_backoff < self.base_backoff:
            raise ValueError("max_backoff must be >= base_backoff")
        if not (0.0 <= self.jitter_ratio <= 1.0):
            raise ValueError("jitter_ratio must be between 0.0 and 1.0")


@dataclass(slots=True)
class Message:
    """Provider-neutral representation of an email message and its envelope metadata."""

    source_id: str
    raw_rfc822: bytes
    rfc822_msgid: str | None = None
    internal_date: datetime | None = None
    labels: tuple[str, ...] = ()
    thread_id: str | None = None
    is_draft: bool = False
    is_deleted: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def size_bytes(self) -> int:
        """Byte length of the raw RFC 822 payload."""
        return len(self.raw_rfc822)

    def with_updates(self, **changes: Any) -> Message:
        """Return a shallow copy of this message with updated fields."""
        return replace(self, **changes)


@dataclass(frozen=True, slots=True)
class TransferResult:
    """Outcome of transferring a single message into a Sink."""

    source_id: str
    status: TransferStatus
    destination_id: str | None = None
    error_message: str | None = None
    retryable: bool = False
    bytes_transferred: int = 0
    sanitized: bool = False


@dataclass(frozen=True, slots=True)
class StreamTelemetry:
    """Snapshot of live AdaptiveStreamController metrics."""

    target_streams: int
    peak_streams: int
    in_flight_streams: int
    ssthresh: int | None
    throttle_events: int
    completed_operations: int
    throughput_rps: float


@dataclass(slots=True)
class JobMetadata:
    """Persistent summary metadata for a transfer job."""

    job_id: str
    action: str
    source_uri: str
    sink_uri: str
    state: JobState
    started_at: datetime
    finished_at: datetime | None = None
    query: str | None = None
    total_discovered: int = 0
    succeeded: int = 0
    skipped: int = 0
    failed: int = 0
    bytes_transferred: int = 0
    peak_streams: int = 0
    avg_throughput_rps: float = 0.0
    throttle_events: int = 0
