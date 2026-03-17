"""
Errors for Double Ratchet (client).
"""

from __future__ import annotations


class RatchetError(Exception):
    """Base for double ratchet errors."""


class DuplicateMessageError(RatchetError):
    """Message number already processed (replay)."""


class SkippedKeyNotFoundError(RatchetError):
    """No skipped key for (dh_pub, n)."""


class SkippedKeyStorageLimitError(RatchetError):
    """Skipped key store capacity exceeded."""


class InvalidHeaderError(RatchetError):
    """Invalid or missing header fields."""


class DecryptionError(RatchetError):
    """AEAD verification failed or corrupted ciphertext."""


class CorruptedSessionError(RatchetError):
    """Session file invalid or corrupted."""


class SessionRollbackError(RatchetError):
    """Session file was replaced with an older version (rollback detected)."""


# --- X3DH session establishment ---


class X3DHInitializationError(RatchetError):
    """Invalid X3DH initialization (bad bundle, key lengths, or missing fields)."""


class OneTimePreKeyReuseError(RatchetError):
    """One-time prekey already used or invalid OPK id."""


class SignedPreKeyVerificationError(RatchetError):
    """Signed prekey signature verification failed."""


class TranscriptMismatchError(RatchetError):
    """Session transcript does not match (binding verification failed)."""


class AlgorithmSuiteMismatchError(RatchetError):
    """Algorithm suite mismatch or downgrade attempt (e.g. hybrid vs classical-only)."""
