"""Generic core exceptions for ngyb."""

from __future__ import annotations


class NGYBError(Exception):
    """Base exception for all ngyb errors."""


class ConfigurationError(NGYBError):
    """Raised when configuration, URIs, or CLI parameters are invalid."""


class AuthenticationError(NGYBError):
    """Raised when DPoP or ADC authentication setup or refresh fails."""


class TransientTransferError(NGYBError):
    """Raised on retryable transport, rate-limit, or server errors."""

    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class PermanentTransferError(NGYBError):
    """Raised when a message permanently cannot be fetched or imported."""
