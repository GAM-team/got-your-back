"""Unit tests for the generic multi-threaded TransferPipeline."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from types import TracebackType
from typing import Self

from gyb.core import (
    AdaptiveStreamController,
    Capability,
    JobState,
    Message,
    PermanentTransferError,
    StreamTuningConfig,
    TransferPipeline,
    TransferResult,
    TransferStatus,
    TransientTransferError,
)


class InMemorySource:
    def __init__(
        self,
        items: dict[str, Message],
        *,
        caps: Capability = (
            Capability.STREAMING_FETCH
            | Capability.MULTIPLEXED_STREAMS
            | Capability.LABEL_SUPPORT
            | Capability.QUERY_FILTERING
        ),
        transient_fetch_counts: dict[str, int] | None = None,
        fail_ids: dict[str, Exception] | None = None,
    ) -> None:
        self._items = items
        self._caps = caps
        self._transient_fetch_counts = dict(transient_fetch_counts or {})
        self._fail_ids = fail_ids or {}
        self._lock = threading.Lock()
        self.fetch_calls: dict[str, int] = {}
        self.connected = False
        self.closed = False
        self.last_query: str | None = None

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def capabilities(self) -> Capability:
        return self._caps

    def connect(self) -> None:
        self.connected = True

    def list_messages(self, query: str | None = None) -> Iterator[str]:
        self.last_query = query
        yield from self._items.keys()

    def fetch_message(self, source_id: str) -> Message:
        with self._lock:
            self.fetch_calls[source_id] = self.fetch_calls.get(source_id, 0) + 1
            if (
                source_id in self._transient_fetch_counts
                and self._transient_fetch_counts[source_id] > 0
            ):
                self._transient_fetch_counts[source_id] -= 1
                raise TransientTransferError("Source 503", retry_after=0.01)
            if source_id in self._fail_ids:
                raise self._fail_ids[source_id]
        return self._items[source_id]

    def close(self) -> None:
        self.closed = True


class InMemorySink:
    def __init__(
        self,
        *,
        caps: Capability = (
            Capability.STREAMING_INSERT | Capability.MULTIPLEXED_STREAMS | Capability.LABEL_SUPPORT
        ),
    ) -> None:
        self._caps = caps
        self._lock = threading.Lock()
        self.connected = False
        self.closed = False
        self.imported: dict[str, Message] = {}
        self.transient_counts: dict[str, int] = {}
        self.result_retryable_counts: dict[str, int] = {}
        self.permanent_fail_ids: set[str] = set()
        self.unexpected_error_ids: set[str] = set()
        self.skip_ids: set[str] = set()

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def capabilities(self) -> Capability:
        return self._caps

    def connect(self) -> None:
        self.connected = True

    def import_message(self, message: Message) -> TransferResult:
        sid = message.source_id
        with self._lock:
            if sid in self.transient_counts and self.transient_counts[sid] > 0:
                self.transient_counts[sid] -= 1
                raise TransientTransferError("429 Too Many Requests", retry_after=0.01)
            if sid in self.result_retryable_counts and self.result_retryable_counts[sid] > 0:
                self.result_retryable_counts[sid] -= 1
                return TransferResult(
                    source_id=sid,
                    status=TransferStatus.FAILED,
                    error_message="503 Backend Error",
                    retryable=True,
                )
            if sid in self.permanent_fail_ids:
                raise PermanentTransferError("Message exceeds 25MB limit")
            if sid in self.unexpected_error_ids:
                raise RuntimeError("boom")
            if sid in self.skip_ids:
                return TransferResult(source_id=sid, status=TransferStatus.SKIPPED)
            self.imported[sid] = message
            return TransferResult(
                source_id=sid,
                status=TransferStatus.SUCCESS,
                destination_id=f"dest-{sid}",
                bytes_transferred=message.size_bytes,
            )

    def close(self) -> None:
        self.closed = True


def test_pipeline_happy_path_with_skip_and_callbacks() -> None:
    items = {
        f"m{i}": Message(
            source_id=f"m{i}",
            raw_rfc822=f"Subject: {i}\r\n\r\nhi".encode(),
            labels=("INBOX",),
        )
        for i in range(10)
    }
    source = InMemorySource(items)
    sink = InMemorySink()
    sink.skip_ids.add("m9")

    tuning = StreamTuningConfig(
        initial_streams=4,
        min_streams=1,
        max_streams=8,
        base_backoff=0.01,
        max_backoff=0.05,
    )
    ctrl = AdaptiveStreamController(tuning, sleep=lambda _: None)
    recorded: list[tuple[TransferResult, int]] = []
    discovered_counts: list[int] = []

    pipeline = TransferPipeline(
        source,
        sink,
        tuning=tuning,
        controller=ctrl,
        on_result=lambda res, att: recorded.append((res, att)),
        on_discovered=discovered_counts.append,
        skip_source_ids={"m0"},
        max_item_retries=3,
    )
    assert pipeline.controller is ctrl

    summary = pipeline.run(query="newer_than:1d")
    assert source.connected and source.closed
    assert sink.connected and sink.closed
    assert source.last_query == "newer_than:1d"
    assert summary.state == JobState.COMPLETED
    assert summary.total_discovered == 10
    assert summary.succeeded == 8
    assert summary.skipped == 2
    assert summary.failed == 0
    assert summary.bytes_transferred > 0
    assert len(recorded) == 10
    assert discovered_counts[-1] == 10


def test_pipeline_separates_fetch_and_import_retries() -> None:
    items = {f"id-{i}": Message(source_id=f"id-{i}", raw_rfc822=b"raw") for i in range(9)}
    source = InMemorySource(
        items,
        caps=Capability.STREAMING_FETCH,
        transient_fetch_counts={
            "id-6": 1,  # transient fetch once, then succeeds
            "id-7": 5,  # exhausts fetch retries
        },
        fail_ids={
            "id-8": PermanentTransferError("missing uid"),
            "id-err": RuntimeError("disk io error"),
        },
    )
    items["id-err"] = Message(source_id="id-err", raw_rfc822=b"raw")

    class NonRetryableResultSink(InMemorySink):
        def import_message(self, message: Message) -> TransferResult:
            if message.source_id == "id-5":
                return TransferResult(
                    source_id="id-5",
                    status=TransferStatus.FAILED,
                    error_message="corrupt mime",
                    retryable=False,
                )
            return super().import_message(message)

    custom_sink = NonRetryableResultSink(caps=Capability.STREAMING_INSERT)
    # id-0: sink transient error once -> source is NOT re-fetched!
    custom_sink.transient_counts["id-0"] = 1
    custom_sink.result_retryable_counts["id-1"] = 1
    custom_sink.transient_counts["id-2"] = 5
    custom_sink.permanent_fail_ids.add("id-3")
    custom_sink.unexpected_error_ids.add("id-4")

    tuning = StreamTuningConfig(
        initial_streams=1,
        min_streams=1,
        max_streams=2,
        base_backoff=0.01,
        max_backoff=0.02,
    )
    ctrl = AdaptiveStreamController(tuning, sleep=lambda _: None)
    attempts_by_id: dict[str, int] = {}

    pipeline = TransferPipeline(
        source,
        custom_sink,
        tuning=tuning,
        controller=ctrl,
        on_result=lambda res, att: attempts_by_id.__setitem__(res.source_id, att),
        max_item_retries=2,
    )
    summary = pipeline.run(explicit_ids=list(items.keys()))
    assert summary.state == JobState.COMPLETED_WITH_ERRORS
    # id-0, id-1, id-6 succeed!
    assert summary.succeeded == 3
    assert summary.failed == 7
    # Crucial verification: sink retry on id-0 only fetched from source ONCE!
    assert source.fetch_calls["id-0"] == 1
    assert source.fetch_calls["id-6"] == 2
    assert source.fetch_calls["id-7"] == 2
    assert attempts_by_id["id-0"] == 2
    assert attempts_by_id["id-6"] == 2
    assert attempts_by_id["id-7"] == 2
    assert attempts_by_id["id-8"] == 1
    assert attempts_by_id["id-err"] == 1

    minimal_source = InMemorySource({"only": Message(source_id="only", raw_rfc822=b"ok")})
    minimal_sink = InMemorySink()
    minimal_summary = TransferPipeline(minimal_source, minimal_sink).run()
    assert minimal_summary.succeeded == 1
