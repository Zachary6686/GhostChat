from __future__ import annotations

"""
Framing utilities (skeleton).

Defines simple length-prefixed frames for sending messages over a
byte-stream transport.
"""

import struct


def encode_frame(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload


def decode_frame(stream: bytes) -> tuple[bytes, bytes] | None:
    if len(stream) < 4:
        return None
    (length,) = struct.unpack("!I", stream[:4])
    if len(stream) < 4 + length:
        return None
    return stream[4 : 4 + length], stream[4 + length :]

