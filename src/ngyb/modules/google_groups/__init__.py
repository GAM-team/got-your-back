"""Google Groups Migration API Sink module."""

from ngyb.modules.google_groups.client import (
    GROUPS_MAX_MESSAGE_BYTES,
    GroupsBadMessageError,
    GroupsMigrationClient,
)
from ngyb.modules.google_groups.sink import GoogleGroupsSink

__all__ = [
    "GROUPS_MAX_MESSAGE_BYTES",
    "GoogleGroupsSink",
    "GroupsBadMessageError",
    "GroupsMigrationClient",
]
