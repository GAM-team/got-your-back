"""Shared Click option decorators for HTTP/2 stream scaling and transfer flags."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import click

from ngyb.core.exceptions import ConfigurationError
from ngyb.core.models import StreamTuningConfig


def stream_tuning_options(func: Callable[..., Any]) -> Callable[..., Any]:
    """Attach user-tunable HTTP/2 AIMD stream scaling flags to a Click command."""
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
        func = opt(func)
    return func


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
