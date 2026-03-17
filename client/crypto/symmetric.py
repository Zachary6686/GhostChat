"""
Symmetric AEAD for GhostChat client.

ChaCha20-Poly1305. Nonce/counter for replay protection.
"""

from __future__ import annotations

import struct
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

NONCE_LENGTH = 12
TAG_LENGTH = 16


def aead_encrypt(key: bytes, plaintext: bytes, nonce: bytes, ad: bytes = b"") -> bytes:
    """
    Encrypt with ChaCha20-Poly1305. key 32 bytes, nonce 12 bytes.
    Returns ciphertext (includes tag).
    """
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != NONCE_LENGTH:
        raise ValueError("nonce must be 12 bytes")
    aead = ChaCha20Poly1305(key)
    return aead.encrypt(nonce, plaintext, ad)


def aead_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, ad: bytes = b"") -> bytes:
    """Decrypt; raises InvalidTag on any auth failure (tag mismatch, wrong AAD, or corruption)."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != NONCE_LENGTH:
        raise ValueError("nonce must be 12 bytes")
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ciphertext, ad)


def nonce_from_counter(counter: int) -> bytes:
    """Deterministic 12-byte nonce from counter (replay protection)."""
    return struct.pack("<Q", counter) + b"\x00\x00\x00\x00"
