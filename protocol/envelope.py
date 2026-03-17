from __future__ import annotations

"""
Canonical protocol envelope for one-to-one messages.

This module defines the canonical envelope format used for pairwise
double-ratchet messages at the protocol layer. It is intentionally
agnostic about the transport (WebSockets, HTTP, etc.).
"""

from dataclasses import dataclass
from typing import Any, Dict

from crypto.serialization import b64u_encode, b64u_decode


CURRENT_VERSION = 1


@dataclass
class ProtocolEnvelope:
    """
    Canonical envelope for a single one-to-one message.

    Fields:
      - version: protocol version number.
      - session_id: opaque identifier for the pairwise session.
      - sender_ratchet_key: current DH ratchet public key of the sender.
      - message_number: position in the current sending chain.
      - previous_chain_length: number of messages in the previous sending chain.
      - ciphertext: AEAD ciphertext produced by the double ratchet layer.
      - nonce: optional explicit nonce; the current double ratchet embeds
        nonce derivation inside the AEAD and sets this to an empty value.
      - meta: optional metadata for diagnostics (non-sensitive).
    """

    version: int
    session_id: bytes
    sender_ratchet_key: bytes
    message_number: int
    previous_chain_length: int
    ciphertext: bytes
    nonce: bytes
    meta: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "v": self.version,
            "sid": b64u_encode(self.session_id),
            "rk": b64u_encode(self.sender_ratchet_key),
            "n": self.message_number,
            "pn": self.previous_chain_length,
            "ct": b64u_encode(self.ciphertext),
            "nonce": b64u_encode(self.nonce),
            "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProtocolEnvelope":
        """
        Parse and validate an envelope from a dict. Raises ValueError on
        malformed or unsupported data.
        """

        try:
            version = int(data.get("v", 0))
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid or missing envelope version") from exc
        if version != CURRENT_VERSION:
            raise ValueError("Unsupported envelope version")

        try:
            sid = b64u_decode(data["sid"])
            rk = b64u_decode(data["rk"])
            ct = b64u_decode(data["ct"])
            nonce = b64u_decode(data.get("nonce", ""))
            n = int(data["n"])
            pn = int(data["pn"])
        except KeyError as exc:
            raise ValueError(f"Missing envelope field: {exc}") from exc
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid envelope field type") from exc

        if n < 0 or pn < 0:
            raise ValueError("Negative message numbers are invalid")
        if not sid or not rk or not ct:
            raise ValueError("Session id, ratchet key, and ciphertext must be non-empty")

        meta_raw = data.get("meta") or {}
        if not isinstance(meta_raw, dict):
            raise ValueError("meta must be a dict if present")

        return cls(
            version=version,
            session_id=sid,
            sender_ratchet_key=rk,
            message_number=n,
            previous_chain_length=pn,
            ciphertext=ct,
            nonce=nonce,
            meta=meta_raw,
        )


