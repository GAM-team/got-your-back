"""Got Your Back (GYB) 2.0 — Modular HTTP/2 email backup, restore, and migration."""

from __future__ import annotations

import modern_httplib2

# Ensure google-api-python-client and google-auth-httplib2 transparently use modern_httplib2.
modern_httplib2.patch()

__version__ = "2.0.0a1"

__all__ = ["__version__"]
