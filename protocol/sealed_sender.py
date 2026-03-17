from __future__ import annotations

"""
Sealed sender protocol layer.

Outer envelope contains only routing data (recipient locator, ttl, opaque
sealed payload). Sender identity and session metadata are inside the
sealed payload, encrypted so only the recipient can recover them.
Prototype: metadata minimization, not perfect anonymity.
"""

import os
import struct
from dataclasses import dataclass
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from crypto.hkdf import hkdf_derive
from crypto.serialization import b64u_decode, b64u_encode

from .message_format import InnerSenderPackage


SEALED_SENDER_VERSION = 1
SEAL_INFO = b"ghostchat-sealed-sender-v1"
NONCE_SIZE = 12


def derive_sealing_key(root_key: bytes) -> bytes:
    """Derive the per-session key used to seal/unseal the inner sender package."""
    return hkdf_derive(ikm=root_key, salt=b"", info=SEAL_INFO, length=32)


def _serialize_inner(inner: InnerSenderPackage) -> bytes:
    """Length-prefixed binary serialization of the inner sender package."""
    parts = [
        struct.pack(">H", len(inner.sender_id)),
        inner.sender_id,
        struct.pack(">H", len(inner.session_id)),
        inner.session_id,
        struct.pack(">H", len(inner.dh_pub)),
        inner.dh_pub,
        struct.pack(">I", inner.pn & 0xFFFF_FFFF),
        struct.pack(">I", inner.n & 0xFFFF_FFFF),
        struct.pack(">I", len(inner.ciphertext)),
        inner.ciphertext,
    ]
    return b"".join(parts)


def _parse_inner(data: bytes) -> InnerSenderPackage:
    """Parse inner sender package from bytes. Raises ValueError if malformed."""
    offset = 0

    def read_u16() -> int:
        nonlocal offset
        if offset + 2 > len(data):
            raise ValueError("Inner package truncated (u16)")
        v = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2
        return v

    def read_u32() -> int:
        nonlocal offset
        if offset + 4 > len(data):
            raise ValueError("Inner package truncated (u32)")
        v = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4
        return v

    def read_bytes(n: int) -> bytes:
        nonlocal offset
        if offset + n > len(data):
            raise ValueError("Inner package truncated (bytes)")
        out = data[offset : offset + n]
        offset += n
        return out

    len_sid = read_u16()
    sender_id = read_bytes(len_sid)
    len_sess = read_u16()
    session_id = read_bytes(len_sess)
    len_dh = read_u16()
    dh_pub = read_bytes(len_dh)
    pn = read_u32()
    n = read_u32()
    len_ct = read_u32()
    ciphertext = read_bytes(len_ct)
    if offset != len(data):
        raise ValueError("Inner package has trailing bytes")

    if not sender_id or not session_id or not dh_pub:
        raise ValueError("Inner package has empty required field")

    return InnerSenderPackage(
        sender_id=sender_id,
        session_id=session_id,
        dh_pub=dh_pub,
        pn=pn,
        n=n,
        ciphertext=ciphertext,
    )


def _aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, ad: bytes = b"") -> bytes:
    aead = ChaCha20Poly1305(key)
    return aead.encrypt(nonce, plaintext, ad)


def _aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, ad: bytes = b"") -> bytes:
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ciphertext, ad)


def seal(inner: InnerSenderPackage, sealing_key: bytes) -> bytes:
    """
    Encrypt the inner sender package. Returns nonce || ciphertext so the
    whole blob can be stored as opaque sealed_payload.
    """
    plaintext = _serialize_inner(inner)
    nonce = os.urandom(NONCE_SIZE)
    ct = _aead_encrypt(sealing_key, nonce, plaintext, ad=b"")
    return nonce + ct


def unseal(sealed_payload: bytes, sealing_key: bytes) -> InnerSenderPackage:
    """
    Decrypt and parse the inner sender package. Raises ValueError if
    malformed or authentication fails.
    """
    if len(sealed_payload) < NONCE_SIZE + 16:  # nonce + poly1305 tag
        raise ValueError("Sealed payload too short")
    nonce = sealed_payload[:NONCE_SIZE]
    ciphertext = sealed_payload[NONCE_SIZE:]
    plaintext = _aead_decrypt(sealing_key, nonce, ciphertext, ad=b"")
    return _parse_inner(plaintext)


@dataclass
class SealedOuterEnvelope:
    """
    Outer envelope for sealed sender. Relay routes using recipient_locator
    only; sender identity is not in plaintext.
    """

    version: int
    recipient_locator: str
    ttl: int
    sealed_payload: bytes
    padding: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "v": self.version,
            "recipient_locator": self.recipient_locator,
            "ttl": self.ttl,
            "sp": b64u_encode(self.sealed_payload),
            "pad": b64u_encode(self.padding) if self.padding else "",
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SealedOuterEnvelope":
        """Parse and validate. Raises ValueError on malformed data."""
        try:
            version = int(data.get("v", 0))
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid or missing sealed envelope version") from exc
        if version != SEALED_SENDER_VERSION:
            raise ValueError("Unsupported sealed envelope version")

        recipient_locator = data.get("recipient_locator")
        if not isinstance(recipient_locator, str) or not recipient_locator.strip():
            raise ValueError("Missing or invalid recipient_locator")

        try:
            ttl = int(data.get("ttl", 0))
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid ttl") from exc
        if ttl < 0:
            raise ValueError("ttl must be non-negative")

        sp = data.get("sp")
        if not sp:
            raise ValueError("Missing sealed payload (sp)")
        try:
            sealed_payload = b64u_decode(sp)
        except Exception as exc:
            raise ValueError("Invalid sealed payload encoding") from exc
        if len(sealed_payload) < NONCE_SIZE + 16:
            raise ValueError("Sealed payload too short")

        pad_raw = data.get("pad") or ""
        padding = b64u_decode(pad_raw) if pad_raw else b""
        if not isinstance(padding, bytes):
            padding = b""

        return cls(
            version=version,
            recipient_locator=recipient_locator,
            ttl=ttl,
            sealed_payload=sealed_payload,
            padding=padding,
        )


def is_sealed_envelope(data: Dict[str, Any]) -> bool:
    """Return True if the dict looks like a sealed sender outer envelope."""
    return isinstance(data, dict) and "sp" in data and "recipient_locator" in data


def make_dummy_sealed_outer(
    recipient_locator: str,
    ttl: int = 0,
    payload_size: int = 64,
) -> Dict[str, Any]:
    """
    Build a dummy outer envelope with the same shape as a real sealed sender
    envelope. The sealed payload is random; no session can decrypt it.
    Used for dummy/cover traffic so the relay cannot distinguish from real.
    """
    # Minimum viable sealed payload: nonce (12) + poly1305 tag (16) + some bytes
    size = max(payload_size, NONCE_SIZE + 16)
    sp = os.urandom(size)
    return {
        "v": SEALED_SENDER_VERSION,
        "recipient_locator": recipient_locator,
        "ttl": ttl,
        "sp": b64u_encode(sp),
        "pad": "",
    }
