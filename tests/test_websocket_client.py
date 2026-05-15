from __future__ import annotations

import asyncio
import base64
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client.crypto.ratchet_errors import DecryptionError
from client.network.websocket_client import GhostChatWebSocketClient


def test_double_ratchet_recv_rejects_plaintext_fallback_payload() -> None:
    """When Double Ratchet is active, malformed payloads must fail closed."""
    client = GhostChatWebSocketClient(uri="ws://example.invalid/ws", username="alice")
    client.set_double_ratchet(object())
    forged_payload = base64.urlsafe_b64encode(b"forged plaintext").decode("ascii").rstrip("=")
    client._recv_queue.put_nowait({"from": "mallory", "payload": forged_payload})

    with pytest.raises(DecryptionError):
        asyncio.run(client.recv_message())
