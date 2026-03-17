from __future__ import annotations

"""
Post-quantum KEM abstraction for GhostChat.

Defines a small interface for ML-KEM / Kyber that can be wired to a real
implementation. Ships with a clearly marked non-cryptographic dummy backend
for testing and development; production MUST replace with a certified KEM.
"""

import os
from dataclasses import dataclass
from typing import Protocol, Tuple

from .hkdf import hkdf_derive

# Algorithm suite identifiers for transcript binding and domain separation.
# Used when combining classical + PQ secrets so downgrade/mismatch can be rejected.
ALGORITHM_SUITE_CLASSICAL: bytes = b"ghostchat-x25519-only-v1"
ALGORITHM_SUITE_HYBRID_KYBER: bytes = b"ghostchat-x25519-kyber768-v1"


class PQKEMBackend(Protocol):
    """
    Minimal KEM interface used by the X3DH hybrid handshake.
    Real deployments must use an ML-KEM (Kyber) implementation satisfying this protocol.
    """

    def algorithm_suite(self) -> bytes:
        """Return the algorithm suite identifier for this backend (e.g. ALGORITHM_SUITE_HYBRID_KYBER)."""

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Return (public_key, secret_key)."""

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Return (ciphertext, shared_secret) for the given public key."""

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Recover shared_secret from ciphertext using the secret key."""


@dataclass
class DummyPQKEM:
    """
    NON-CRYPTOGRAPHIC dummy KEM backend for tests and development.

    Intended STRICTLY for unit tests and API integration. Does NOT provide
    post-quantum security. Production MUST use a real ML-KEM/Kyber backend.
    """

    name: str = "dummy-pqkem-v0"

    def algorithm_suite(self) -> bytes:
        return ALGORITHM_SUITE_HYBRID_KYBER

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        # For a dummy KEM, treat the "public key" as random bytes and the
        # "secret key" as an independent random string.
        pk = os.urandom(32)
        sk = os.urandom(32)
        return pk, sk

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        # Derive a "shared secret" deterministically from the public key and
        # a random nonce, then treat that as both the ciphertext input and
        # KDF input. This is intentionally simple and not a real KEM.
        nonce = os.urandom(16)
        ct = public_key + nonce
        shared = hkdf_derive(
            ikm=ct,
            salt=b"ghostchat-dummy-pqkem-salt",
            info=b"ghostchat-dummy-pqkem-shared",
            length=32,
        )
        return ct, shared

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        # Mirror the derivation used in encapsulate; the dummy backend does
        # not actually use the secret key. This is acceptable only because
        # the backend is explicitly non-production.
        return hkdf_derive(
            ikm=ciphertext,
            salt=b"ghostchat-dummy-pqkem-salt",
            info=b"ghostchat-dummy-pqkem-shared",
            length=32,
        )


def get_testing_pq_backend() -> PQKEMBackend:
    """
    Return a dummy PQ KEM backend for tests.

    A real deployment MUST replace this with a Kyber / ML-KEM implementation
    that satisfies the `PQKEMBackend` protocol.
    """

    return DummyPQKEM()

