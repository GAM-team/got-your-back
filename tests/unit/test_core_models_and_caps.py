"""Unit tests for core models, exceptions, capabilities, and protocol conformance."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from ngyb import __version__
from ngyb.core import (
    AuthenticationError,
    Capability,
    ConfigurationError,
    JobMetadata,
    JobState,
    Message,
    NGYBError,
    PermanentTransferError,
    Sink,
    Source,
    StreamTuningConfig,
    TransferPlan,
    TransferResult,
    TransferStatus,
    TransientTransferError,
)


def test_version_and_exceptions() -> None:
    assert __version__.startswith("2.0.0")
    err = TransientTransferError("rate limited", retry_after=3.5)
    assert isinstance(err, NGYBError)
    assert err.retry_after == 3.5
    assert issubclass(ConfigurationError, NGYBError)
    assert issubclass(AuthenticationError, NGYBError)
    assert issubclass(PermanentTransferError, NGYBError)


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"min_streams": 0}, "min_streams must be >= 1"),
        ({"min_streams": 4, "initial_streams": 2}, "initial_streams must be >= min_streams"),
        ({"initial_streams": 16, "max_streams": 8}, "max_streams must be >= initial_streams"),
        ({"ramp_step": 0}, "ramp_step must be >= 1"),
        ({"ramp_interval": 0.0}, "ramp_interval must be > 0"),
        ({"backoff_decrease_factor": 0.0}, "backoff_decrease_factor"),
        ({"backoff_decrease_factor": 1.0}, "backoff_decrease_factor"),
        ({"base_backoff": 0.0}, "base_backoff must be > 0"),
        ({"base_backoff": 10.0, "max_backoff": 5.0}, "max_backoff must be >= base_backoff"),
        ({"jitter_ratio": -0.1}, "jitter_ratio must be between"),
        ({"jitter_ratio": 1.1}, "jitter_ratio must be between"),
    ],
)
def test_stream_tuning_config_validation(kwargs: dict[str, float | int], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        StreamTuningConfig(**kwargs)  # type: ignore[arg-type]


def test_message_and_job_metadata_models() -> None:
    now = datetime.now(tz=UTC)
    msg = Message(
        source_id="m1",
        raw_rfc822=b"Subject: hi\r\n\r\nbody",
        rfc822_msgid="<id@example.com>",
        internal_date=now,
        labels=("INBOX", "Work"),
        thread_id="t1",
    )
    assert msg.size_bytes == len(msg.raw_rfc822)
    updated = msg.with_updates(labels=("INBOX",), is_draft=True)
    assert updated.labels == ("INBOX",)
    assert updated.is_draft is True
    assert msg.labels == ("INBOX", "Work")

    job = JobMetadata(
        job_id="job-1",
        action="backup",
        source_uri="gmail://u@example.com",
        sink_uri="local:///tmp/archive",
        state=JobState.RUNNING,
        started_at=now,
    )
    assert job.state == JobState.RUNNING


def test_capability_negotiation_and_message_adaptation() -> None:
    src_caps = (
        Capability.STREAMING_FETCH
        | Capability.MULTIPLEXED_STREAMS
        | Capability.LABEL_SUPPORT
        | Capability.PRESERVE_THREAD_ID
        | Capability.QUERY_FILTERING
    )
    sink_full = (
        Capability.STREAMING_INSERT
        | Capability.MULTIPLEXED_STREAMS
        | Capability.LABEL_SUPPORT
        | Capability.PRESERVE_THREAD_ID
        | Capability.SERVER_DEDUPLICATION
    )
    plan_full = TransferPlan.negotiate(src_caps, sink_full)
    assert plan_full.multiplexed is True
    assert plan_full.preserve_labels is True
    assert plan_full.preserve_threads is True
    assert plan_full.query_supported is True
    assert plan_full.server_deduplication is True

    msg = Message(source_id="1", raw_rfc822=b"raw", labels=("A",), thread_id="th1")
    assert plan_full.adapt_message(msg) is msg

    sink_minimal = Capability.STREAMING_INSERT
    plan_min = TransferPlan.negotiate(Capability.STREAMING_FETCH, sink_minimal)
    assert plan_min.multiplexed is False
    assert plan_min.preserve_labels is False
    assert plan_min.preserve_threads is False
    assert plan_min.query_supported is False
    assert plan_min.server_deduplication is False

    adapted = plan_min.adapt_message(msg)
    assert adapted.labels == ()
    assert adapted.thread_id is None


def test_runtime_checkable_protocols() -> None:
    class DummySource:
        @property
        def capabilities(self) -> Capability:
            return Capability.STREAMING_FETCH

        def connect(self) -> None:
            pass

        def list_messages(self, query: str | None = None) -> Iterator[str]:
            _ = query
            return iter(())

        def fetch_message(self, source_id: str) -> Message:
            return Message(source_id=source_id, raw_rfc822=b"")

        def close(self) -> None:
            pass

    class DummySink:
        @property
        def capabilities(self) -> Capability:
            return Capability.STREAMING_INSERT

        def connect(self) -> None:
            pass

        def import_message(self, message: Message) -> TransferResult:
            return TransferResult(source_id=message.source_id, status=TransferStatus.SUCCESS)

        def close(self) -> None:
            pass

    src = DummySource()
    snk = DummySink()
    assert isinstance(src, Source)
    assert isinstance(snk, Sink)
    src.connect()
    assert list(src.list_messages()) == []
    assert src.fetch_message("x").source_id == "x"
    src.close()
    snk.connect()
    assert (
        snk.import_message(Message(source_id="x", raw_rfc822=b"")).status == TransferStatus.SUCCESS
    )
    snk.close()
