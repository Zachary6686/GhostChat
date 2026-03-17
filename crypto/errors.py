from __future__ import annotations


class GhostChatCryptoError(Exception):
    """Base class for cryptographic errors in GhostChat."""


class InvalidSignatureError(GhostChatCryptoError):
    """Raised when a signature verification fails."""


class InvalidKeyFormatError(GhostChatCryptoError):
    """Raised when serialized key material is malformed or has an unknown version."""


class OneTimePreKeyExhaustedError(GhostChatCryptoError):
    """Raised when attempting to consume an unavailable or already-used one-time pre-key."""

