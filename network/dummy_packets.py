from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict

from protocol.sealed_sender import make_dummy_sealed_outer


@dataclass
class DummyPacket:
    """
    Dummy packet that is intended to be indistinguishable from a real
    sealed-sender envelope at the network layer.

    The `is_dummy` flag is kept only locally and MUST NOT be serialized
    into on-the-wire metadata if stronger indistinguishability is desired.
    """

    envelope: Dict[str, Any]
    is_dummy: bool = True


def make_dummy_sealed_envelope(
    recipient_locator: str,
    ttl: int = 0,
    payload_size: int = 64,
) -> DummyPacket:
    """
    Create a dummy packet in sealed sender outer format. Indistinguishable
    from real traffic at the relay; recipient will fail to decrypt and
    should drop it without affecting session state.
    """
    envelope = make_dummy_sealed_outer(
        recipient_locator=recipient_locator,
        ttl=ttl,
        payload_size=payload_size,
    )
    return DummyPacket(envelope=envelope)


def make_dummy_envelope_like(real_envelope: Dict[str, Any]) -> DummyPacket:
    """
    Create a dummy envelope that matches the structure of `real_envelope`
    but contains random ciphertext payloads and neutral routing fields.
    """

    dummy = dict(real_envelope)  # shallow copy of structure

    # Randomize ciphertext-like fields if present.
    if "ciphertext" in dummy and isinstance(dummy["ciphertext"], (bytes, bytearray)):
        dummy["ciphertext"] = os.urandom(len(dummy["ciphertext"]))
    elif "payload" in dummy and isinstance(dummy["payload"], (bytes, bytearray)):
        dummy["payload"] = os.urandom(len(dummy["payload"]))
    if "sp" in dummy and isinstance(dummy["sp"], str):
        # Sealed payload: replace with random base64-like length
        from crypto.serialization import b64u_encode
        dummy["sp"] = b64u_encode(os.urandom(64))

    # Recipient fields may be left as-is or set to a neutral value depending
    # on the routing policy; here we keep them unchanged to mimic a real
    # delivery pattern.

    # TTL or expiry fields can be set to a minimal value, causing the relay
    # to discard promptly after routing.
    if "ttl" in dummy:
        dummy["ttl"] = 0

    return DummyPacket(envelope=dummy)

