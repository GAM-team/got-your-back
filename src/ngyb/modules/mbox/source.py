"""Streaming mbox / Google Takeout / Google Vault Source module."""

from __future__ import annotations

import csv
import re
import threading
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from dataclasses import dataclass
from email import policy
from email.header import decode_header
from email.parser import BytesHeaderParser
from pathlib import Path

from ngyb.core.capabilities import Capability
from ngyb.core.exceptions import ConfigurationError, PermanentTransferError
from ngyb.core.models import Message
from ngyb.modules.local.schema import extract_msgid_and_date
from ngyb.modules.mbox.labellang import normalize_takeout_label

_MBOXRD_UNESCAPE = re.compile(rb"(?m)^>(>*From )")


def decode_rfc2047_text(raw_value: str) -> str:
    """Decode RFC 2047 encoded words in an X-Gmail-Labels header value."""
    chunks: list[str] = []
    for part, charset in decode_header(raw_value):
        if isinstance(part, bytes):
            enc = charset or "utf-8"
            try:
                chunks.append(part.decode(enc, errors="replace"))
            except LookupError:
                chunks.append(part.decode("utf-8", errors="replace"))
        else:
            chunks.append(part)
    return "".join(chunks)


def parse_label_string(raw_labels: str) -> tuple[tuple[str, ...], bool]:
    """Parse a comma-separated X-Gmail-Labels or Vault Labels string.

    Returns ``(deduplicated_labels, is_deleted)``.
    """
    decoded = decode_rfc2047_text(raw_labels).replace("\r", "").replace("\n", " ").strip()
    if not decoded:
        return (), False

    row = next(csv.reader([decoded], skipinitialspace=True), [])
    result: list[str] = []
    seen: set[str] = set()
    is_deleted = False
    for token in row:
        norm, deleted_flag = normalize_takeout_label(token)
        if deleted_flag:
            is_deleted = True
        if norm is not None and norm not in seen:
            seen.add(norm)
            result.append(norm)
    return tuple(result), is_deleted


def _load_vault_xml_labels(xml_path: Path) -> dict[str, str]:
    """Map ExternalFile FileName -> Labels string from a Google Vault metadata XML."""
    mapping: dict[str, str] = {}
    root = ET.parse(xml_path).getroot()
    for doc in root.findall(".//Document"):
        labels_val: str | None = None
        for tag in doc.findall("./Tags/Tag"):
            if tag.attrib.get("TagName") == "Labels":
                labels_val = tag.attrib.get("TagValue", "")
                break
        if labels_val is not None:
            for ext in doc.findall("./Files/File/ExternalFile"):
                fname = ext.attrib.get("FileName")
                if fname:
                    mapping[fname] = labels_val
    return mapping


def _load_vault_csv_labels(csv_path: Path) -> dict[str, str]:
    """Map Rfc822MessageId -> Labels string from a Google Vault metadata CSV."""
    mapping: dict[str, str] = {}
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "Rfc822MessageId" not in reader.fieldnames:
            return mapping
        for row in reader:
            msgid = (row.get("Rfc822MessageId") or "").strip()
            labels = (row.get("Labels") or "").strip()
            if msgid and labels:
                mapping[msgid] = labels
    return mapping


@dataclass(frozen=True, slots=True)
class _MboxEntry:
    mbox_path: Path
    start_offset: int
    end_offset: int
    envelope_file_key: str | None


def _parse_envelope_file_key(from_line: bytes) -> str | None:
    """Extract Google Vault ExternalFile key from 'From <file>@xxx ...' line."""
    parts = from_line.split()
    if len(parts) >= 2:
        sender = parts[1].decode("utf-8", errors="replace")
        local_part = sender.split("@", 1)[0]
        if local_part.endswith(".mbox"):
            return local_part
    return None


def _index_mbox_file(mbox_path: Path) -> list[_MboxEntry]:
    """Stream an mbox file once to record random-access byte offsets per message."""
    entries: list[_MboxEntry] = []
    current_start: int | None = None
    current_key: str | None = None

    with mbox_path.open("rb") as fh:
        while True:
            line_offset = fh.tell()
            line = fh.readline()
            if not line:
                if current_start is not None:
                    entries.append(
                        _MboxEntry(
                            mbox_path=mbox_path,
                            start_offset=current_start,
                            end_offset=line_offset,
                            envelope_file_key=current_key,
                        )
                    )
                break
            if line.startswith(b"From "):
                if current_start is not None:
                    entries.append(
                        _MboxEntry(
                            mbox_path=mbox_path,
                            start_offset=current_start,
                            end_offset=line_offset,
                            envelope_file_key=current_key,
                        )
                    )
                current_start = fh.tell()
                current_key = _parse_envelope_file_key(line)
    return entries


class MboxSource:
    """Thread-safe streaming Source for .mbox files, Google Takeout, and Google Vault."""

    def __init__(self, path: Path) -> None:
        self._path = path.expanduser().resolve()
        self._entries: dict[str, _MboxEntry] = {}
        self._vault_file_labels: dict[str, str] = {}
        self._vault_msgid_labels: dict[str, str] = {}
        self._connected = False
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def capabilities(self) -> Capability:
        return (
            Capability.STREAMING_FETCH | Capability.MULTIPLEXED_STREAMS | Capability.LABEL_SUPPORT
        )

    def connect(self) -> None:
        if not self._path.exists():
            raise ConfigurationError(f"mbox path does not exist: {self._path}")

        mbox_files: list[Path]
        vault_file_map: dict[str, str] = {}
        vault_msgid_map: dict[str, str] = {}

        if self._path.is_file():
            mbox_files = [self._path]
            parent = self._path.parent
            for xml_file in sorted(parent.glob("*metadata*.xml")):
                vault_file_map.update(_load_vault_xml_labels(xml_file))
            for csv_file in sorted(parent.glob("*.csv")):
                vault_msgid_map.update(_load_vault_csv_labels(csv_file))
        else:
            mbox_files = sorted(
                p
                for p in self._path.rglob("*")
                if p.is_file() and p.suffix.lower() in {".mbox", ".mbx"}
            )
            if not mbox_files:
                raise ConfigurationError(f"No .mbox or .mbx files found under: {self._path}")
            for xml_file in sorted(self._path.rglob("*.xml")):
                vault_file_map.update(_load_vault_xml_labels(xml_file))
            for csv_file in sorted(self._path.rglob("*.csv")):
                vault_msgid_map.update(_load_vault_csv_labels(csv_file))

        indexed: dict[str, _MboxEntry] = {}
        for f_idx, mbox_file in enumerate(mbox_files):
            for m_idx, entry in enumerate(_index_mbox_file(mbox_file)):
                source_id = f"{mbox_file.name}:{f_idx}:{m_idx}"
                indexed[source_id] = entry

        with self._lock:
            self._entries = indexed
            self._vault_file_labels = vault_file_map
            self._vault_msgid_labels = vault_msgid_map
            self._connected = True

    def list_messages(self, query: str | None = None) -> Iterator[str]:
        _ = query
        with self._lock:
            if not self._connected:
                raise ConfigurationError("MboxSource is not connected.")
            keys = list(self._entries.keys())
        yield from keys

    def fetch_message(self, source_id: str) -> Message:
        with self._lock:
            if not self._connected:
                raise ConfigurationError("MboxSource is not connected.")
            entry = self._entries.get(source_id)
            if entry is None:
                raise PermanentTransferError(f"mbox entry {source_id!r} not found.")

        length = max(0, entry.end_offset - entry.start_offset)
        with entry.mbox_path.open("rb") as fh:
            fh.seek(entry.start_offset)
            raw_chunk = fh.read(length)

        # Strip single trailing blank separator line added by mbox format
        if raw_chunk.endswith(b"\r\n\r\n"):
            raw_chunk = raw_chunk[:-2]
        elif raw_chunk.endswith(b"\n\n"):
            raw_chunk = raw_chunk[:-1]

        raw_rfc822 = _MBOXRD_UNESCAPE.sub(rb"\1", raw_chunk)
        headers = BytesHeaderParser(policy=policy.compat32).parsebytes(raw_rfc822)
        msgid, parsed_dt = extract_msgid_and_date(raw_rfc822)

        combined_labels: list[str] = []
        seen_labels: set[str] = set()
        is_deleted = False

        label_sources: list[str] = []
        for hdr_val in headers.get_all("X-Gmail-Labels", []):
            label_sources.append(str(hdr_val))
        if entry.envelope_file_key and entry.envelope_file_key in self._vault_file_labels:
            label_sources.append(self._vault_file_labels[entry.envelope_file_key])
        if msgid and msgid in self._vault_msgid_labels:
            label_sources.append(self._vault_msgid_labels[msgid])

        for raw_label_str in label_sources:
            parsed_labels, deleted_flag = parse_label_string(raw_label_str)
            if deleted_flag:
                is_deleted = True
            for lbl in parsed_labels:
                if lbl not in seen_labels:
                    seen_labels.add(lbl)
                    combined_labels.append(lbl)

        labels_tuple = tuple(combined_labels)
        is_draft = any(lbl.upper() == "DRAFT" for lbl in labels_tuple)
        return Message(
            source_id=source_id,
            raw_rfc822=raw_rfc822,
            rfc822_msgid=msgid,
            internal_date=parsed_dt,
            labels=labels_tuple,
            is_draft=is_draft,
            is_deleted=is_deleted,
        )

    def close(self) -> None:
        with self._lock:
            self._entries.clear()
            self._connected = False
