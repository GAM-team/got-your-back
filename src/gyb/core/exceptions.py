"""Generic core exceptions for GYB."""

from __future__ import annotations


class GYBError(Exception):
    """Base exception for all GYB errors."""


class ConfigurationError(GYBError):
    """Raised when configuration, URIs, or CLI parameters are invalid."""


class AuthenticationError(GYBError):
    """Raised when DPoP or ADC authentication setup or refresh fails."""


class TransientTransferError(GYBError):
    """Raised on retryable transport, rate-limit, or server errors."""

    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class PermanentTransferError(GYBError):
    """Raised when a message permanently cannot be fetched or imported."""
