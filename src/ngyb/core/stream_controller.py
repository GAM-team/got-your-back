"""AIMD dynamic HTTP/2 stream concurrency controller with global coordinated backoff."""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from ngyb.core.models import StreamTelemetry, StreamTuningConfig


class AdaptiveStreamController:
    """Regulates concurrent stream permits using AIMD and global backoff coordination.

    - Starts at ``config.initial_streams``.
    - Doubles stream target during slow-start (up to ``ssthresh`` or ``max_streams``)
      when streams are utilized and throughput is healthy.
    - Increases linearly by ``config.ramp_step`` per ``config.ramp_interval`` during
      congestion avoidance.
    - On server throttle/backoff, coalesces simultaneous in-flight burst notifications,
      multiplicatively lowers ``target_streams`` and ``ssthresh``, and pauses all worker
      threads globally for jittered exponential backoff (or explicit ``retry_after``).
    """

    def __init__(
        self,
        config: StreamTuningConfig,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        rng: Callable[[], float] = random.random,
    ) -> None:
        self._config = config
        self._clock = clock
        self._sleep = sleep
        self._rng = rng
        self._cond = threading.Condition(threading.Lock())

        now = self._clock()
        self._started_at = now
        self._window_start = now
        self._target_streams = config.initial_streams
        self._peak_streams = config.initial_streams
        self._in_flight = 0
        self._ssthresh: int | None = None
        self._consecutive_throttles = 0
        self._throttle_events = 0
        self._paused_until = 0.0
        self._window_completed = 0
        self._total_completed = 0
        self._prev_rps = 0.0
        self._current_rps = 0.0
        self._saturated_in_window = False

    @property
    def config(self) -> StreamTuningConfig:
        """Active stream tuning parameters."""
        return self._config

    def telemetry(self) -> StreamTelemetry:
        """Return a thread-safe snapshot of stream scaling metrics."""
        with self._cond:
            return StreamTelemetry(
                target_streams=self._target_streams,
                peak_streams=self._peak_streams,
                in_flight_streams=self._in_flight,
                ssthresh=self._ssthresh,
                throttle_events=self._throttle_events,
                completed_operations=self._total_completed,
                throughput_rps=self._current_rps,
            )

    def avg_throughput_rps(self) -> float:
        """Overall average completed operations per second since controller start."""
        with self._cond:
            elapsed = max(0.001, self._clock() - self._started_at)
            return self._total_completed / elapsed

    def wait_if_paused(self) -> None:
        """Block the caller while a global coordinated backoff window is active."""
        while True:
            with self._cond:
                remaining = self._paused_until - self._clock()
            if remaining <= 0:
                return
            self._sleep(remaining)

    def acquire(self) -> None:
        """Acquire an active stream permit, waiting through global pauses and capacity limits."""
        while True:
            with self._cond:
                now = self._clock()
                remaining = self._paused_until - now
                if remaining <= 0:
                    if self._in_flight < self._target_streams:
                        self._in_flight += 1
                        if self._in_flight >= self._target_streams:
                            self._saturated_in_window = True
                        return
                    self._cond.wait(timeout=0.05)
                    continue
            self._sleep(remaining)

    def release(self) -> None:
        """Release an active stream permit and wake waiting worker threads."""
        with self._cond:
            if self._in_flight > 0:
                self._in_flight -= 1
            self._cond.notify_all()

    @contextmanager
    def stream_permit(self) -> Iterator[None]:
        """Context manager acquiring and releasing one dynamic stream permit."""
        self.acquire()
        try:
            yield
        finally:
            self.release()

    def report_success(self, latency_seconds: float = 0.0) -> None:
        """Record a clean operation and evaluate AIMD ramp-up when a window completes."""
        _ = latency_seconds
        with self._cond:
            now = self._clock()
            self._consecutive_throttles = 0
            self._total_completed += 1
            self._window_completed += 1

            elapsed = now - self._window_start
            if elapsed >= self._config.ramp_interval:
                window_rps = self._window_completed / elapsed
                self._current_rps = window_rps
                utilized = (
                    self._saturated_in_window or self._window_completed >= self._target_streams
                )
                improving = self._prev_rps == 0.0 or window_rps >= self._prev_rps * 0.85

                if now >= self._paused_until and utilized and improving:
                    if self._ssthresh is None or self._target_streams < self._ssthresh:
                        next_target = self._target_streams * 2
                        if self._ssthresh is not None and next_target > self._ssthresh:
                            next_target = self._ssthresh
                    else:
                        next_target = self._target_streams + self._config.ramp_step

                    self._target_streams = min(self._config.max_streams, next_target)
                    if self._target_streams > self._peak_streams:
                        self._peak_streams = self._target_streams
                    self._prev_rps = window_rps
                    self._cond.notify_all()

                self._window_start = now
                self._window_completed = 0
                self._saturated_in_window = self._in_flight >= self._target_streams

    def report_throttle(self, retry_after: float | None = None) -> float:
        """Coordinate global exponential backoff and multiplicative stream reduction.

        Returns the active backoff pause duration in seconds.
        """
        with self._cond:
            now = self._clock()
            if now < self._paused_until:
                remaining = self._paused_until - now
                if retry_after is not None:
                    capped_retry = min(self._config.max_backoff, retry_after)
                    if capped_retry > remaining:
                        self._paused_until = now + capped_retry
                        self._window_start = self._paused_until
                        remaining = capped_retry
                return remaining

            self._throttle_events += 1
            self._consecutive_throttles += 1

            reduced = max(
                self._config.min_streams,
                int(self._target_streams * self._config.backoff_decrease_factor),
            )
            self._ssthresh = reduced
            self._target_streams = (
                reduced if self._consecutive_throttles == 1 else self._config.min_streams
            )

            exp_delay = min(
                self._config.max_backoff,
                self._config.base_backoff * (2 ** (self._consecutive_throttles - 1)),
            )
            jitter = 1.0 + ((self._rng() * 2.0 - 1.0) * self._config.jitter_ratio)
            delay = max(0.01, min(self._config.max_backoff, exp_delay * jitter))

            if retry_after is not None:
                capped_retry = min(self._config.max_backoff, retry_after)
                if capped_retry > delay:
                    delay = capped_retry

            self._paused_until = now + delay
            self._window_start = self._paused_until
            self._window_completed = 0
            self._prev_rps = 0.0
            self._saturated_in_window = False
            return delay
