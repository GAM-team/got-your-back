"""Gmail system/reserved label transformation and thread-safe label cache."""

from __future__ import annotations

import threading
from collections.abc import Iterable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ngyb.modules.gmail.client import GmailClient

GMAIL_SYSTEM_LABELS: frozenset[str] = frozenset(
    {
        "INBOX",
        "SPAM",
        "TRASH",
        "UNREAD",
        "STARRED",
        "IMPORTANT",
        "SENT",
        "DRAFT",
        "CATEGORY_PERSONAL",
        "CATEGORY_SOCIAL",
        "CATEGORY_PROMOTIONS",
        "CATEGORY_UPDATES",
        "CATEGORY_FORUMS",
    }
)

GMAIL_IMPORTABLE_SYSTEM_LABELS: frozenset[str] = GMAIL_SYSTEM_LABELS - {"DRAFT"}

SKIPPED_SOURCE_LABELS: frozenset[str] = frozenset({"CHAT", "CHATS"})

RESERVED_USER_LABEL_ROOTS: frozenset[str] = frozenset(
    {
        "inbox",
        "spam",
        "trash",
        "unread",
        "starred",
        "important",
        "sent",
        "draft",
        "chat",
        "chats",
        "migrated",
        "todo",
        "todos",
        "buzz",
        "bin",
        "allmail",
        "drafts",
        "archive",
        "archived",
        "muted",
    }
)


def transform_label_for_gmail(
    raw_label: str,
    *,
    label_prefix: str | None = None,
) -> str | None:
    """Transform a source label into a valid Gmail system or user label name."""
    cleaned = raw_label.strip().strip("/")
    if not cleaned:
        return None

    upper = cleaned.upper()
    if upper in SKIPPED_SOURCE_LABELS:
        user_label = "Chats_restored"
    elif upper in GMAIL_SYSTEM_LABELS:
        return upper
    else:
        root = cleaned.split("/", 1)[0].lower()
        user_label = f"_{cleaned}" if root in RESERVED_USER_LABEL_ROOTS else cleaned

    if label_prefix:
        prefix_clean = label_prefix.strip().strip("/")
        if prefix_clean:
            root_prefix = prefix_clean.split("/", 1)[0].lower()
            if root_prefix in RESERVED_USER_LABEL_ROOTS:
                prefix_clean = f"_{prefix_clean}"
            return f"{prefix_clean}/{user_label}"
    return user_label


class GmailLabelManager:
    """Thread-safe cache and creator for Gmail user and system labels."""

    def __init__(self, client: GmailClient) -> None:
        self._client = client
        self._lock = threading.Lock()
        self._name_to_id: dict[str, str] = {}
        self._id_to_name: dict[str, str] = {}

    def refresh(self) -> None:
        """Reload all labels from the Gmail API."""
        items = self._client.list_labels()
        with self._lock:
            self._name_to_id.clear()
            self._id_to_name.clear()
            for item in items:
                lid = str(item["id"])
                name = str(item["name"])
                self._name_to_id[name.lower()] = lid
                self._id_to_name[lid] = name

    def resolve_id_to_name(self, label_id: str) -> str:
        """Map a Gmail label ID to its human-readable name."""
        with self._lock:
            cached = self._id_to_name.get(label_id)
        if cached is not None:
            return cached
        self.refresh()
        with self._lock:
            return self._id_to_name.get(label_id, label_id)

    def _ensure_single_user_label(self, label_name: str) -> str:
        key = label_name.lower()
        with self._lock:
            existing = self._name_to_id.get(key)
        if existing is not None:
            return existing

        created = self._client.create_label(label_name)
        if created is not None:
            lid = str(created["id"])
            name = str(created.get("name", label_name))
            with self._lock:
                self._name_to_id[name.lower()] = lid
                self._name_to_id[key] = lid
                self._id_to_name[lid] = name
            return lid

        # 409 Conflict from another worker thread: refresh cache and resolve
        self.refresh()
        with self._lock:
            resolved = self._name_to_id.get(key)
        if resolved is not None:
            return resolved
        raise RuntimeError(f"Unable to resolve Gmail label {label_name!r} after 409 Conflict.")

    def ensure_label_id(self, label_name: str) -> str:
        """Return Gmail label ID for a system or nested user label (creating parents first)."""
        upper = label_name.upper()
        if upper in GMAIL_IMPORTABLE_SYSTEM_LABELS:
            return upper

        parts = [seg for seg in label_name.split("/") if seg]
        accumulated: list[str] = []
        last_id = ""
        for seg in parts:
            accumulated.append(seg)
            full = "/".join(accumulated)
            last_id = self._ensure_single_user_label(full)
        return last_id

    def prepare_import_labels(
        self,
        source_labels: Iterable[str],
        *,
        strip_labels: bool = False,
        label_prefix: str | None = None,
        label_restored: str | None = None,
    ) -> tuple[list[str], bool]:
        """Convert source labels into Gmail labelIds and a draft indicator."""
        is_draft = False
        target_names: list[str] = []

        if not strip_labels:
            for raw in source_labels:
                transformed = transform_label_for_gmail(raw, label_prefix=label_prefix)
                if transformed is None:
                    continue
                if transformed == "DRAFT":
                    is_draft = True
                    continue
                target_names.append(transformed)
        else:
            for raw in source_labels:
                if raw.strip().upper() == "DRAFT":
                    is_draft = True

        if label_restored:
            extra = transform_label_for_gmail(label_restored)
            if extra and extra != "DRAFT":
                target_names.append(extra)

        label_ids: list[str] = []
        seen_ids: set[str] = set()
        for name in target_names:
            lid = self.ensure_label_id(name)
            if lid and lid not in seen_ids:
                seen_ids.add(lid)
                label_ids.append(lid)
        return label_ids, is_draft
