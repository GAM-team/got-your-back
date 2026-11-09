"""Strict Source and Sink protocols for GYB modules."""

from __future__ import annotations

from collections.abc import Iterator
from types import TracebackType
from typing import Protocol, Self, runtime_checkable

from gyb.core.capabilities import Capability
from gyb.core.models import Message, TransferResult


@runtime_checkable
class Source(Protocol):
    """Protocol that every mail import/backup source module must implement."""

    @property
    def capabilities(self) -> Capability: ...

    def connect(self) -> None: ...

    def list_messages(self, query: str | None = None) -> Iterator[str]: ...

    def fetch_message(self, source_id: str) -> Message: ...

    def close(self) -> None: ...

    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...


@runtime_checkable
class Sink(Protocol):
    """Protocol that every mail export/restore destination module must implement."""

    @property
    def capabilities(self) -> Capability: ...

    def connect(self) -> None: ...

    def import_message(self, message: Message) -> TransferResult: ...

    def close(self) -> None: ...

    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...
