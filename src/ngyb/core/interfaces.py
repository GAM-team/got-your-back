"""Strict Source and Sink protocols for ngyb modules."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol, runtime_checkable

from ngyb.core.capabilities import Capability
from ngyb.core.models import Message, TransferResult


@runtime_checkable
class Source(Protocol):
    """Protocol that every mail import/backup source module must implement."""

    @property
    def capabilities(self) -> Capability: ...

    def connect(self) -> None: ...

    def list_messages(self, query: str | None = None) -> Iterator[str]: ...

    def fetch_message(self, source_id: str) -> Message: ...

    def close(self) -> None: ...


@runtime_checkable
class Sink(Protocol):
    """Protocol that every mail export/restore destination module must implement."""

    @property
    def capabilities(self) -> Capability: ...

    def connect(self) -> None: ...

    def import_message(self, message: Message) -> TransferResult: ...

    def close(self) -> None: ...
