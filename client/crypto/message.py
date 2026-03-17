"""
Double Ratchet message format for wire/serialization.

Header: dh (sender ratchet public key), n (message number), pn (previous chain length).
Ciphertext and nonce; header may be visible, plaintext never sent.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Dict

from client.crypto.ratchet_errors import InvalidHeaderError


MAX_CIPHERTEXT_LEN = 1024 * 1024  # 1 MiB upper bound to mitigate DoS on huge payloads


def b64_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def b64_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


@dataclass
class RatchetMessageHeader:
    """Header sent with each encrypted message."""
    dh: bytes   # sender ratchet public key (32 bytes)
    n: int      # message number in current sending chain
    pn: int     # previous chain length


@dataclass
class RatchetWireMessage:
    """Full wire message: header + ciphertext + nonce."""
    header: RatchetMessageHeader
    ciphertext: bytes
    nonce: bytes


def wire_message_to_dict(msg: RatchetWireMessage) -> Dict[str, Any]:
    """Serialize for JSON (e.g. over WebSocket)."""
    return {
        "header": {
            "dh": b64_encode(msg.header.dh),
            "n": msg.header.n,
            "pn": msg.header.pn,
        },
        "ciphertext": b64_encode(msg.ciphertext),
        "nonce": b64_encode(msg.nonce),
    }


def _require_int32(name: str, value: Any) -> int:
    """Require value to be an int in [0, 2^32-1]. Raises InvalidHeaderError otherwise."""
    if value is None:
        raise InvalidHeaderError(f"missing {name}")
    if not isinstance(value, int):
        raise InvalidHeaderError(f"{name} must be an integer")
    if isinstance(value, bool):
        raise InvalidHeaderError(f"{name} must be an integer")
    if value < 0 or value > 0xFFFF_FFFF:
        raise InvalidHeaderError(f"{name} must be in range [0, 2^32-1]")
    return value


def wire_message_from_dict(data: Dict[str, Any]) -> RatchetWireMessage:
    """
    Parse from JSON. Validates all required fields and types.
    Raises InvalidHeaderError on missing, wrong type, or out-of-range data.
    """
    if not isinstance(data, dict):
        raise InvalidHeaderError("message must be a dict")
    h = data.get("header")
    if not h or not isinstance(h, dict):
        raise InvalidHeaderError("missing header")
    dh_b64 = h.get("dh")
    if dh_b64 is None:
        raise InvalidHeaderError("missing header field dh")
    if not isinstance(dh_b64, str) or dh_b64 == "":
        raise InvalidHeaderError("header field dh must be a non-empty string")
    try:
        dh = b64_decode(dh_b64)
    except Exception as e:
        raise InvalidHeaderError(f"invalid dh encoding: {e}") from e
    if len(dh) != 32:
        raise InvalidHeaderError("dh must be 32 bytes")
    n = _require_int32("n", h.get("n"))
    pn = _require_int32("pn", h.get("pn"))
    header = RatchetMessageHeader(dh=dh, n=n, pn=pn)
    ct_b64 = data.get("ciphertext")
    nonce_b64 = data.get("nonce")
    if ct_b64 is None:
        raise InvalidHeaderError("missing ciphertext")
    if not isinstance(ct_b64, str):
        raise InvalidHeaderError("ciphertext must be a string")
    if nonce_b64 is None:
        raise InvalidHeaderError("missing nonce")
    if not isinstance(nonce_b64, str) or nonce_b64 == "":
        raise InvalidHeaderError("nonce must be a non-empty string")
    try:
        ciphertext = b64_decode(ct_b64)
        nonce = b64_decode(nonce_b64)
    except Exception as e:
        raise InvalidHeaderError(f"invalid base64: {e}") from e
    if len(nonce) != 12:
        raise InvalidHeaderError("nonce must be 12 bytes")
    # ChaCha20-Poly1305 tag is 16 bytes; ciphertext must be at least that.
    if len(ciphertext) < 16:
        raise InvalidHeaderError("ciphertext too short (invalid or truncated)")
    if len(ciphertext) > MAX_CIPHERTEXT_LEN:
        raise InvalidHeaderError("ciphertext too large")
    return RatchetWireMessage(header=header, ciphertext=ciphertext, nonce=nonce)
