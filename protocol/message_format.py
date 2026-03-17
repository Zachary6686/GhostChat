from __future__ import annotations

"""
Common message format helpers.

This module separates the outer protocol envelope from the inner
encrypted payload. It is designed to be extensible to sealed sender and
group messaging.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class SessionPayload:
    """
    Inner payload for a one-to-one session message before it is wrapped
    in a protocol envelope.

    In the current design, this is essentially the double-ratchet
    ciphertext and its associated header encoded as bytes.
    """

    header_bytes: bytes
    ciphertext: bytes


@dataclass
class OuterEnvelope:
    """
    Outer envelope combining routing information (e.g., mailbox ID) and
    the serialized protocol envelope. This is suitable for sealed sender
    integration in future work.
    """

    recipient: Optional[str]
    ttl: int
    protocol_envelope_bytes: bytes


@dataclass
class GroupMessageEnvelope:
    """
    Outer container for a group message on the wire.
    recipient_locator is used for routing (e.g. group_id hex or b64).
    payload is the serialized GroupMessage (to_dict).
    """

    recipient_locator: str
    payload: dict


def group_message_envelope_to_dict(group_id: bytes, payload: dict) -> dict:
    """Build relay-routable dict for a group message. Uses b64 group_id as locator."""
    from crypto.serialization import b64u_encode
    return {
        "recipient_locator": b64u_encode(group_id),
        "group_message": payload,
    }


def group_message_envelope_from_dict(data: dict) -> tuple[bytes, dict]:
    """Parse relay envelope; returns (group_id_bytes, payload)."""
    from crypto.serialization import b64u_decode
    locator = data.get("recipient_locator")
    payload = data.get("group_message")
    if not locator or not isinstance(payload, dict):
        raise ValueError("Invalid group message envelope")
    return b64u_decode(locator), payload


@dataclass
class InnerSenderPackage:
    """
    Protected sender metadata and payload for sealed sender.

    Only the recipient can recover this after decrypting the sealed
    payload with the session-derived sealing key. The relay never sees
    these fields in plaintext.
    """

    sender_id: bytes
    session_id: bytes
    dh_pub: bytes
    pn: int
    n: int
    ciphertext: bytes

