"""
Key agreement for GhostChat client.

X25519 ECDH with interface prepared for future ML-KEM (Kyber).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol

from nacl.public import PrivateKey as X25519PrivateKey
from nacl.public import PublicKey as X25519PublicKey
from nacl.public import Box

from crypto.hkdf import hkdf_derive

# Future: from cryptography.hazmat.primitives.asymmetric.x25519 import ...


class PQKEMProtocol(Protocol):
    """Protocol for future post-quantum KEM (e.g. ML-KEM)."""

    def encapsulate(self, peer_public_key: bytes) -> tuple[bytes, bytes]:
        """Generate shared secret and ciphertext for peer."""
        ...

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Recover shared secret from ciphertext."""
        ...


@dataclass
class KeyExchange:
    """
    Hybrid key exchange: X25519 + optional PQ component.
    perform_handshake(peer_pubkey) derives shared secret using X25519.
    """

    ephemeral_private: X25519PrivateKey
    pq_backend: Optional[PQKEMProtocol] = None

    @classmethod
    def generate_ephemeral(cls) -> "KeyExchange":
        """Generate a new ephemeral key pair for this handshake."""
        return cls(ephemeral_private=X25519PrivateKey.generate())

    def get_ephemeral_public(self) -> bytes:
        """Public key to send to peer (32 bytes)."""
        return bytes(self.ephemeral_private.public_key)

    def derive_shared_secret(self, peer_public_key: bytes) -> bytes:
        """
        X25519 ECDH with peer's public key.
        Returns 32-byte shared secret. Optionally combine with PQ later.
        """
        peer_pub = X25519PublicKey(peer_public_key)
        box = Box(self.ephemeral_private, peer_pub)
        classical = box._shared_key  # 32 bytes

        if self.pq_backend is not None:
            # Future: combine classical + pq_secret via HKDF
            raise NotImplementedError("PQ KEM not yet wired")

        return classical

    @staticmethod
    def derive_root_key(shared_secret: bytes, salt: bytes = b"", info: bytes = b"ghostchat-kex-root") -> bytes:
        """HKDF: shared secret -> root key for ratchet."""
        return hkdf_derive(ikm=shared_secret, salt=salt, info=info, length=32)


def perform_handshake(peer_pubkey: bytes) -> tuple[KeyExchange, bytes]:
    """
    Initiator: generate ephemeral, derive shared secret and root key.
    Returns (KeyExchange instance, root_key).
    """
    kex = KeyExchange.generate_ephemeral()
    secret = kex.derive_shared_secret(peer_pubkey)
    root_key = KeyExchange.derive_root_key(secret)
    return kex, root_key
