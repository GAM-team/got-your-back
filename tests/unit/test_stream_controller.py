"""Unit tests for AdaptiveStreamController AIMD scaling and global backoff."""

from __future__ import annotations

import threading

from ngyb.core.models import StreamTuningConfig
from ngyb.core.stream_controller import AdaptiveStreamController


class FakeClock:
    def __init__(self, initial: float = 100.0) -> None:
        self.now = initial
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, duration: float) -> None:
        self.slept.append(duration)
        self.now += duration


def test_slow_start_throttle_and_congestion_avoidance() -> None:
    clock = FakeClock()
    cfg = StreamTuningConfig(
        initial_streams=4,
        min_streams=1,
        max_streams=20,
        ramp_interval=1.0,
        ramp_step=3,
        backoff_decrease_factor=0.5,
        base_backoff=2.0,
        max_backoff=10.0,
        jitter_ratio=0.0,
    )
    ctrl = AdaptiveStreamController(cfg, clock=clock, sleep=clock.sleep, rng=lambda: 0.5)
    assert ctrl.config == cfg
    assert ctrl.telemetry().target_streams == 4

    # Window 1: complete 4 ops over 1.0s -> slow start doubles 4 -> 8
    for _ in range(3):
        ctrl.report_success(0.05)
    clock.now += 1.0
    ctrl.report_success(0.05)
    assert ctrl.telemetry().target_streams == 8
    assert ctrl.telemetry().peak_streams == 8

    # Window 2: saturate in_flight via stream_permit, double 8 -> 16
    for _ in range(8):
        ctrl.acquire()
    for _ in range(8):
        ctrl.release()
    for _ in range(7):
        ctrl.report_success()
    clock.now += 1.0
    ctrl.report_success()
    assert ctrl.telemetry().target_streams == 16

    # Trigger server throttle: 16 * 0.5 -> ssthresh = 8, target = 8, pause = 2.0s
    delay = ctrl.report_throttle()
    assert delay == 2.0
    assert ctrl.telemetry().target_streams == 8
    assert ctrl.telemetry().ssthresh == 8
    assert ctrl.telemetry().throttle_events == 1

    # Simultaneous burst throttle during active pause coalesces without slashing again!
    assert ctrl.report_throttle() == 2.0
    coalesced_short = ctrl.report_throttle(retry_after=0.5)
    assert coalesced_short == 2.0
    assert ctrl.telemetry().target_streams == 8
    assert ctrl.telemetry().throttle_events == 1

    # Explicit larger retry_after during active pause extends pause window
    coalesced_long = ctrl.report_throttle(retry_after=5.0)
    assert coalesced_long == 5.0
    assert ctrl.telemetry().target_streams == 8

    # Global pause blocks wait_if_paused() and advances fake clock by 5.0s
    ctrl.wait_if_paused()
    assert clock.slept == [5.0]
    # Calling wait_if_paused when not paused returns immediately
    ctrl.wait_if_paused()
    assert clock.slept == [5.0]

    # Now at target == ssthresh (8): clean window uses congestion avoidance (+3 -> 11)
    for _ in range(7):
        ctrl.report_success()
    clock.now += 1.0
    ctrl.report_success()
    assert ctrl.telemetry().target_streams == 11

    # Average throughput calculation
    assert ctrl.avg_throughput_rps() > 0.0


def test_slow_start_caps_at_ssthresh_and_skips_unutilized_window() -> None:
    clock = FakeClock()
    cfg = StreamTuningConfig(
        initial_streams=6,
        min_streams=2,
        max_streams=32,
        ramp_interval=1.0,
        ramp_step=2,
        backoff_decrease_factor=0.5,
        base_backoff=1.0,
        max_backoff=10.0,
        jitter_ratio=0.0,
    )
    ctrl = AdaptiveStreamController(cfg, clock=clock, sleep=clock.sleep, rng=lambda: 0.5)

    # First double 6 -> 12
    for _ in range(5):
        ctrl.report_success()
    clock.now += 1.0
    ctrl.report_success()
    assert ctrl.telemetry().target_streams == 12

    # Throttle 1 with explicit retry_after -> ssthresh = 6, target = 6
    d1 = ctrl.report_throttle(retry_after=4.0)
    assert d1 == 4.0
    assert ctrl.telemetry().ssthresh == 6
    clock.now += 4.0

    # Consecutive Throttle 2 -> ssthresh = 3, target drops to min_streams = 2
    d2 = ctrl.report_throttle()
    assert d2 == 2.0
    assert ctrl.telemetry().ssthresh == 3
    assert ctrl.telemetry().target_streams == 2
    clock.now += 2.0

    # Unutilized window (only 1 op when target is 2) does not ramp
    clock.now += 1.0
    ctrl.report_success()
    assert ctrl.telemetry().target_streams == 2

    # Utilized window slow-starts 2*2=4, clamped to ssthresh=3!
    ctrl.report_success()
    clock.now += 1.0
    ctrl.report_success()
    assert ctrl.telemetry().target_streams == 3

    # Extra release() when in_flight == 0 is a safe no-op
    ctrl.release()
    assert ctrl.telemetry().in_flight_streams == 0


def test_acquire_blocks_when_at_capacity_and_during_pause() -> None:
    clock = FakeClock()
    cfg = StreamTuningConfig(
        initial_streams=1,
        min_streams=1,
        max_streams=4,
        base_backoff=1.5,
        max_backoff=5.0,
        jitter_ratio=0.0,
    )
    ctrl = AdaptiveStreamController(cfg, clock=clock, sleep=clock.sleep, rng=lambda: 0.5)

    # Pause via throttle -> acquire() sleeps through the pause window
    ctrl.report_throttle()
    with ctrl.stream_permit():
        assert ctrl.telemetry().in_flight_streams == 1
    assert clock.slept == [1.5]
    assert ctrl.telemetry().in_flight_streams == 0

    # Now test real thread blocking when permit capacity (1) is exhausted
    real_ctrl = AdaptiveStreamController(cfg)
    entered = threading.Event()
    release_first = threading.Event()
    second_acquired = threading.Event()

    def first_worker() -> None:
        with real_ctrl.stream_permit():
            entered.set()
            release_first.wait(timeout=2.0)

    def second_worker() -> None:
        entered.wait(timeout=2.0)
        with real_ctrl.stream_permit():
            second_acquired.set()

    t1 = threading.Thread(target=first_worker)
    t2 = threading.Thread(target=second_worker)
    t1.start()
    t2.start()
    entered.wait(timeout=2.0)
    # Give t2 a moment to hit _cond.wait()
    assert not second_acquired.wait(timeout=0.08)
    release_first.set()
    assert second_acquired.wait(timeout=2.0)
    t1.join(timeout=2.0)
    t2.join(timeout=2.0)
