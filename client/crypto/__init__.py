"""
Client-side crypto: key exchange, ratchet, symmetric AEAD, PreKey bundle, X3DH.

Extensible for ML-KEM (Kyber) and full double ratchet.
"""

from client.crypto.key_exchange import KeyExchange, perform_handshake
from client.crypto.prekey import (
    ClientPreKeyBundle,
    PeerBundle,
    generate_prekey_bundle,
    serialize_bundle,
    sign_prekey,
)
from client.crypto.ratchet import SessionCrypto, SessionCryptoPair
from client.crypto.symmetric import aead_decrypt, aead_encrypt
from client.crypto.x3dh import x3dh_initiator, x3dh_responder, X3DHResult

__all__ = [
    "KeyExchange",
    "SessionCrypto",
    "SessionCryptoPair",
    "perform_handshake",
    "aead_encrypt",
    "aead_decrypt",
    "ClientPreKeyBundle",
    "PeerBundle",
    "generate_prekey_bundle",
    "serialize_bundle",
    "sign_prekey",
    "x3dh_initiator",
    "x3dh_responder",
    "X3DHResult",
]
