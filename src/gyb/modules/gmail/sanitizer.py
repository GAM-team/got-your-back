"""RFC 822 header hygiene and sanitization for Gmail and Google Groups."""

from __future__ import annotations

from datetime import UTC, datetime
from email import policy
from email.parser import BytesHeaderParser
from email.utils import format_datetime, formataddr, make_msgid, parseaddr, parsedate_to_datetime

GMAIL_MAX_MESSAGE_BYTES = 50 * 1024 * 1024
DEFAULT_FALLBACK_DOMAIN = "gyb-restore.local"
DEFAULT_FALLBACK_FROM = f"gyb-restore@{DEFAULT_FALLBACK_DOMAIN}"


def _clean_single_line(value: str) -> str:
    return " ".join(value.replace("\r", " ").replace("\n", " ").split())


def _is_valid_msgid(value: str | None) -> bool:
    if not value:
        return False
    stripped = value.strip()
    return (
        len(stripped) >= 3
        and stripped.startswith("<")
        and stripped.endswith(">")
        and not any(ch.isspace() for ch in stripped)
    )


def _is_valid_date(value: str | None) -> bool:
    if not value or not value.strip():
        return False
    try:
        parsedate_to_datetime(value)
        return True
    except (TypeError, ValueError, IndexError):
        return False


def _is_valid_from(value: str | None) -> bool:
    if not value or not value.strip():
        return False
    _, addr = parseaddr(value)
    if not addr or "@" not in addr or any(ch.isspace() for ch in addr):
        return False
    local, domain = addr.rsplit("@", 1)
    return bool(local and domain)


def _build_replacement_from(orig_from: str | None, cleanup_from: str | None) -> str:
    display_name, _ = parseaddr(orig_from or "")
    clean_display = _clean_single_line(display_name)
    if cleanup_from:
        fb_display, fb_addr = parseaddr(cleanup_from)
        target_addr = fb_addr or cleanup_from.strip()
        if fb_display:
            return formataddr((fb_display, target_addr))
        if clean_display:
            return formataddr((clean_display, target_addr))
        return target_addr
    if clean_display:
        return formataddr((clean_display, DEFAULT_FALLBACK_FROM))
    return DEFAULT_FALLBACK_FROM


def sanitize_rfc822_message(
    raw_bytes: bytes,
    *,
    cleanup_from: str | None = None,
    fallback_date: datetime | None = None,
) -> tuple[bytes, tuple[str, ...]]:
    """Validate and repair top-level Message-ID, Date, and From headers.

    Preserves the raw MIME body byte-for-byte so binary attachments and legacy
    8-bit parts are never re-encoded or altered.
    """
    if b"\r\n\r\n" in raw_bytes:
        header_bytes, body_bytes = raw_bytes.split(b"\r\n\r\n", 1)
    elif b"\n\n" in raw_bytes:
        header_bytes, body_bytes = raw_bytes.split(b"\n\n", 1)
    else:
        header_bytes, body_bytes = raw_bytes, b""

    header_msg = BytesHeaderParser(policy=policy.compat32).parsebytes(header_bytes)
    changes: list[str] = []

    orig_msgid = header_msg.get("Message-ID")
    if not _is_valid_msgid(str(orig_msgid) if orig_msgid is not None else None):
        if orig_msgid is not None:
            del header_msg["Message-ID"]
            header_msg["X-GYB-Orig-Msg-Id"] = _clean_single_line(str(orig_msgid))
        header_msg["Message-ID"] = make_msgid(domain=DEFAULT_FALLBACK_DOMAIN)
        changes.append("Message-ID")

    orig_date = header_msg.get("Date")
    if not _is_valid_date(str(orig_date) if orig_date is not None else None):
        if orig_date is not None:
            del header_msg["Date"]
            header_msg["X-GYB-Orig-Msg-Date"] = _clean_single_line(str(orig_date))
        eff_dt = fallback_date if fallback_date is not None else datetime.now(tz=UTC)
        if eff_dt.tzinfo is None:
            eff_dt = eff_dt.replace(tzinfo=UTC)
        header_msg["Date"] = format_datetime(eff_dt)
        changes.append("Date")

    orig_from = header_msg.get("From")
    orig_from_str = str(orig_from) if orig_from is not None else None
    if not _is_valid_from(orig_from_str):
        if orig_from is not None:
            del header_msg["From"]
            header_msg["X-GYB-Orig-Msg-From"] = _clean_single_line(orig_from_str or "")
        header_msg["From"] = _build_replacement_from(orig_from_str, cleanup_from)
        changes.append("From")

    if not changes:
        return raw_bytes, ()

    header_msg["X-GYB-Changes-Made"] = ",".join(changes)
    serialized_headers = header_msg.as_bytes(policy=policy.compat32.clone(linesep="\r\n"))
    if not serialized_headers.endswith(b"\r\n\r\n"):
        serialized_headers = serialized_headers.rstrip(b"\r\n") + b"\r\n\r\n"
    return serialized_headers + body_bytes, tuple(changes)
