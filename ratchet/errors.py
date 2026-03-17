from __future__ import annotations


class RatchetError(Exception):
    """Base class for double ratchet related errors."""


class DuplicateMessageError(RatchetError):
    """Raised when a message is detected as a duplicate."""


class SkippedKeyNotFoundError(RatchetError):
    """Raised when a referenced skipped message key cannot be found."""


class SkippedKeyStorageLimitError(RatchetError):
    """Raised when the skipped-key cache would exceed its configured limit."""

