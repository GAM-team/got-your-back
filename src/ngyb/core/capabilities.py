"""Provider-agnostic module capability flags and capability negotiation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Flag, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ngyb.core.models import Message


class Capability(Flag):
    """Capabilities advertised by Source and Sink modules."""

    NONE = 0
    STREAMING_FETCH = auto()
    STREAMING_INSERT = auto()
    MULTIPLEXED_STREAMS = auto()
    LABEL_SUPPORT = auto()
    FOLDER_SUPPORT = auto()
    PRESERVE_THREAD_ID = auto()
    SERVER_DEDUPLICATION = auto()
    QUERY_FILTERING = auto()


@dataclass(frozen=True, slots=True)
class TransferPlan:
    """Effective negotiated capabilities between a Source and a Sink."""

    multiplexed: bool
    preserve_labels: bool
    preserve_threads: bool
    query_supported: bool
    server_deduplication: bool

    @classmethod
    def negotiate(cls, source_caps: Capability, sink_caps: Capability) -> TransferPlan:
        """Negotiate optimal transfer behavior from source and sink capabilities."""
        both_multiplex = bool(
            (source_caps & Capability.MULTIPLEXED_STREAMS)
            and (sink_caps & Capability.MULTIPLEXED_STREAMS)
        )
        preserve_labels = bool(
            (source_caps & (Capability.LABEL_SUPPORT | Capability.FOLDER_SUPPORT))
            and (sink_caps & (Capability.LABEL_SUPPORT | Capability.FOLDER_SUPPORT))
        )
        preserve_threads = bool(
            (source_caps & Capability.PRESERVE_THREAD_ID)
            and (sink_caps & Capability.PRESERVE_THREAD_ID)
        )
        query_supported = bool(source_caps & Capability.QUERY_FILTERING)
        server_dedup = bool(sink_caps & Capability.SERVER_DEDUPLICATION)
        return cls(
            multiplexed=both_multiplex,
            preserve_labels=preserve_labels,
            preserve_threads=preserve_threads,
            query_supported=query_supported,
            server_deduplication=server_dedup,
        )

    def adapt_message(self, message: Message) -> Message:
        """Strip unsupported metadata fields before passing a message to the sink."""
        labels = message.labels if self.preserve_labels else ()
        thread_id = message.thread_id if self.preserve_threads else None
        if labels == message.labels and thread_id == message.thread_id:
            return message
        return message.with_updates(labels=labels, thread_id=thread_id)
