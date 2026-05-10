from __future__ import annotations

import json

import pytest

from client.crypto.ratchet_errors import DecryptionError
from client.network.websocket_client import GhostChatWebSocketClient


class _RejectingDoubleRatchet:
    def ratchet_decrypt(self, _wire: object) -> bytes:
        raise AssertionError("malformed payload must be rejected before decrypt")


@pytest.mark.asyncio
async def test_double_ratchet_recv_rejects_non_ratchet_payload() -> None:
    client = GhostChatWebSocketClient("ws://example.invalid/ws", "bob")
    client.set_double_ratchet(_RejectingDoubleRatchet())
    await client._recv_queue.put({"type": "msg", "from": "alice", "payload": json.dumps({"text": "plain"})})

    with pytest.raises(DecryptionError):
        await client.recv_message()


@pytest.mark.asyncio
async def test_double_ratchet_recv_rejects_invalid_json_payload() -> None:
    client = GhostChatWebSocketClient("ws://example.invalid/ws", "bob")
    client.set_double_ratchet(_RejectingDoubleRatchet())
    await client._recv_queue.put({"type": "msg", "from": "alice", "payload": "not-json"})

    with pytest.raises(DecryptionError):
        await client.recv_message()
