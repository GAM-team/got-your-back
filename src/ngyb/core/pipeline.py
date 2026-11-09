"""Provider-agnostic multi-threaded streaming transfer pipeline."""

from __future__ import annotations

import queue
import threading
import time
from collections.abc import Callable, Collection, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from ngyb.core.capabilities import TransferPlan
from ngyb.core.exceptions import PermanentTransferError, TransientTransferError
from ngyb.core.interfaces import Sink, Source
from ngyb.core.models import (
    JobState,
    StreamTelemetry,
    StreamTuningConfig,
    TransferResult,
    TransferStatus,
)
from ngyb.core.stream_controller import AdaptiveStreamController


class _Sentinel:
    """Internal queue sentinel signaling worker completion."""


_STOP = _Sentinel()


@dataclass(frozen=True, slots=True)
class PipelineRunSummary:
    """Aggregated outcome of a TransferPipeline execution."""

    state: JobState
    plan: TransferPlan
    total_discovered: int
    succeeded: int
    skipped: int
    failed: int
    bytes_transferred: int
    telemetry: StreamTelemetry
    avg_throughput_rps: float


class TransferPipeline:
    """Streams messages from any Source to any Sink with dynamic stream concurrency."""

    def __init__(
        self,
        source: Source,
        sink: Sink,
        *,
        tuning: StreamTuningConfig | None = None,
        controller: AdaptiveStreamController | None = None,
        on_result: Callable[[TransferResult, int], None] | None = None,
        on_discovered: Callable[[int], None] | None = None,
        skip_source_ids: Collection[str] = (),
        max_item_retries: int = 3,
    ) -> None:
        self._source = source
        self._sink = sink
        self._tuning = tuning or StreamTuningConfig()
        self._controller = controller or AdaptiveStreamController(self._tuning)
        self._on_result = on_result
        self._on_discovered = on_discovered
        self._skip_ids = set(skip_source_ids)
        self._max_item_retries = max(1, max_item_retries)

        self._stats_lock = threading.Lock()
        self._discovered = 0
        self._succeeded = 0
        self._skipped = 0
        self._failed = 0
        self._bytes_transferred = 0

    @property
    def controller(self) -> AdaptiveStreamController:
        """Underlying stream concurrency controller."""
        return self._controller

    def _record_result(self, result: TransferResult, attempts: int) -> None:
        with self._stats_lock:
            if result.status == TransferStatus.SUCCESS:
                self._succeeded += 1
                self._bytes_transferred += result.bytes_transferred
            elif result.status == TransferStatus.SKIPPED:
                self._skipped += 1
            else:
                self._failed += 1
        if self._on_result is not None:
            self._on_result(result, attempts)

    def _transfer_single(self, source_id: str, plan: TransferPlan) -> None:
        last_result = TransferResult(
            source_id=source_id,
            status=TransferStatus.FAILED,
            error_message="Transfer did not execute",
        )
        attempts = 0
        for attempt in range(1, self._max_item_retries + 1):
            attempts = attempt
            started = time.monotonic()
            try:
                with self._controller.stream_permit():
                    message = self._source.fetch_message(source_id)
                    adapted = plan.adapt_message(message)
                    result = self._sink.import_message(adapted)
            except TransientTransferError as exc:
                self._controller.report_throttle(exc.retry_after)
                last_result = TransferResult(
                    source_id=source_id,
                    status=TransferStatus.FAILED,
                    error_message=str(exc),
                    retryable=True,
                )
                continue
            except PermanentTransferError as exc:
                last_result = TransferResult(
                    source_id=source_id,
                    status=TransferStatus.FAILED,
                    error_message=str(exc),
                    retryable=False,
                )
                break
            except Exception as exc:
                last_result = TransferResult(
                    source_id=source_id,
                    status=TransferStatus.FAILED,
                    error_message=f"{type(exc).__name__}: {exc}",
                    retryable=False,
                )
                break

            if result.status == TransferStatus.FAILED and result.retryable:
                self._controller.report_throttle()
                last_result = result
                continue

            if result.status in (TransferStatus.SUCCESS, TransferStatus.SKIPPED):
                self._controller.report_success(time.monotonic() - started)
            last_result = result
            break

        self._record_result(last_result, attempts)

    def run(
        self,
        *,
        query: str | None = None,
        explicit_ids: Iterable[str] | None = None,
    ) -> PipelineRunSummary:
        """Connect source & sink, stream transfers concurrently, and return job summary."""
        plan = TransferPlan.negotiate(self._source.capabilities, self._sink.capabilities)
        worker_count = self._tuning.max_streams if plan.multiplexed else 1
        work_queue: queue.Queue[str | _Sentinel] = queue.Queue(maxsize=max(16, worker_count * 2))

        def _worker() -> None:
            while True:
                item = work_queue.get()
                try:
                    if isinstance(item, _Sentinel):
                        return
                    self._transfer_single(item, plan)
                finally:
                    work_queue.task_done()

        self._source.connect()
        try:
            self._sink.connect()
            try:
                effective_query = query if plan.query_supported else None
                id_stream = (
                    explicit_ids
                    if explicit_ids is not None
                    else self._source.list_messages(query=effective_query)
                )

                with ThreadPoolExecutor(
                    max_workers=worker_count, thread_name_prefix="ngyb-stream"
                ) as pool:
                    futures = [pool.submit(_worker) for _ in range(worker_count)]
                    try:
                        for source_id in id_stream:
                            with self._stats_lock:
                                self._discovered += 1
                                current_discovered = self._discovered
                            if self._on_discovered is not None:
                                self._on_discovered(current_discovered)
                            if source_id in self._skip_ids:
                                self._record_result(
                                    TransferResult(
                                        source_id=source_id,
                                        status=TransferStatus.SKIPPED,
                                    ),
                                    attempts=0,
                                )
                                continue
                            work_queue.put(source_id)
                    finally:
                        for _ in range(worker_count):
                            work_queue.put(_STOP)
                        for fut in futures:
                            fut.result()
            finally:
                self._sink.close()
        finally:
            self._source.close()

        telemetry = self._controller.telemetry()
        avg_rps = self._controller.avg_throughput_rps()
        state = JobState.COMPLETED if self._failed == 0 else JobState.COMPLETED_WITH_ERRORS
        return PipelineRunSummary(
            state=state,
            plan=plan,
            total_discovered=self._discovered,
            succeeded=self._succeeded,
            skipped=self._skipped,
            failed=self._failed,
            bytes_transferred=self._bytes_transferred,
            telemetry=telemetry,
            avg_throughput_rps=avg_rps,
        )
