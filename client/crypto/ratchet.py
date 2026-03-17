"""
Double Ratchet–ready session crypto for GhostChat client.

Simplified: root key, chain key, message key derivation.
HKDF (SHA256) + ChaCha20-Poly1305. Replay-safe nonces.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from crypto.hkdf import hkdf_derive

from client.crypto.symmetric import aead_decrypt, aead_encrypt, nonce_from_counter

CHAIN_SEND_INFO = b"ghostchat-ratchet-send"
CHAIN_RECV_INFO = b"ghostchat-ratchet-recv"
MSG_INFO = b"ghostchat-ratchet-msg"
SALT = b"ghostchat-ratchet-salt"


def _derive_chain_and_message_key(chain_key: bytes) -> tuple[bytes, bytes]:
    """KDF_CK(CK) -> (CK', MK)."""
    material = hkdf_derive(ikm=chain_key, salt=SALT, info=MSG_INFO, length=64)
    return material[:32], material[32:64]


@dataclass
class SessionCrypto:
    """
    Double-ratchet-ready: root key, send chain, recv chain.
    Initiator encrypts on send chain, responder decrypts on recv chain (same KDF);
    and vice versa for the other direction.
    """

    root_key: bytes
    send_chain_key: bytes
    recv_chain_key: bytes
    send_message_number: int = 0
    recv_message_number: int = 0

    @classmethod
    def from_root_key(cls, root_key: bytes, is_initiator: bool = True) -> "SessionCrypto":
        """Initialize from handshake root key. Initiator send == responder recv (same KDF)."""
        if len(root_key) != 32:
            raise ValueError("root_key must be 32 bytes")
        key_send = hkdf_derive(ikm=root_key, salt=SALT, info=CHAIN_SEND_INFO, length=32)
        key_recv = hkdf_derive(ikm=root_key, salt=SALT, info=CHAIN_RECV_INFO, length=32)
        if is_initiator:
            send_chain_key, recv_chain_key = key_send, key_recv
        else:
            send_chain_key, recv_chain_key = key_recv, key_send
        return cls(
            root_key=root_key,
            send_chain_key=send_chain_key,
            recv_chain_key=recv_chain_key,
        )

    def encrypt_message(self, plaintext: bytes, ad: bytes = b"") -> bytes:
        """Encrypt with send chain; advance send chain and message number."""
        chain, msg_key = _derive_chain_and_message_key(self.send_chain_key)
        nonce = nonce_from_counter(self.send_message_number)
        ciphertext = aead_encrypt(msg_key, plaintext, nonce, ad)
        payload = struct.pack(">I", self.send_message_number) + nonce + ciphertext
        self.send_chain_key = chain
        self.send_message_number += 1
        return payload

    def decrypt_message(self, payload: bytes, ad: bytes = b"") -> bytes:
        """Decrypt with recv chain; advance recv chain."""
        if len(payload) < 4 + 12:
            raise ValueError("payload too short")
        msg_num = struct.unpack(">I", payload[:4])[0]
        nonce = payload[4:4 + 12]
        ciphertext = payload[4 + 12:]
        chain, msg_key = _derive_chain_and_message_key(self.recv_chain_key)
        plaintext = aead_decrypt(msg_key, ciphertext, nonce, ad)
        self.recv_chain_key = chain
        self.recv_message_number = max(self.recv_message_number, msg_num + 1)
        return plaintext


@dataclass
class SessionCryptoPair:
    """Send and receive session crypto (for one peer). Extensible to asymmetric ratchet."""

    send: SessionCrypto
    recv: SessionCrypto
