"""
Async WebSocket client for GhostChat relay.

Persistent connection; send/recv encrypted messages.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from typing import Any, Dict, Optional

from client.crypto.message import wire_message_from_dict, wire_message_to_dict
from client.crypto.ratchet import SessionCrypto
from client.crypto.ratchet_errors import DecryptionError

logger = logging.getLogger(__name__)


class GhostChatWebSocketClient:
    """
    Maintains persistent WebSocket connection to relay.
    Sends encrypted payloads; receives and decrypts with SessionCrypto (legacy) or DoubleRatchetEngine.
    """

    def __init__(self, uri: str, username: str) -> None:
        self.uri = uri
        self.username = username
        self._ws: Any = None
        self._session: Optional[SessionCrypto] = None
        self._double_ratchet: Any = None  # Optional[DoubleRatchetEngine]
        self._ephemeral_pub_b64: Optional[str] = None
        self._recv_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
        self._init_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()

    async def connect(self) -> None:
        """Connect to relay and register."""
        try:
            import websockets
        except ImportError:
            raise ImportError("websockets package required: pip install websockets") from None

        self._ws = await websockets.connect(
            self.uri,
            ping_interval=20,
            ping_timeout=10,
            close_timeout=5,
        )
        logger.info("Connected to %s", self.uri)

    async def register(self, ephemeral_public_key: bytes) -> None:
        """Register with relay; server stores our ephemeral pubkey for peers."""
        b64 = base64.urlsafe_b64encode(ephemeral_public_key).decode("ascii").rstrip("=")
        self._ephemeral_pub_b64 = b64
        await self._send_json({"type": "register", "username": self.username, "ephemeral_pub": b64})
        msg = await self._recv_json()
        if msg.get("type") == "error":
            raise RuntimeError("Registration failed: %s", msg.get("message", msg))
        if msg.get("type") != "registered" and not (
            msg.get("type") == "ok" and msg.get("message") == "registered"
        ):
            raise RuntimeError("Registration failed: %s", msg)

    async def get_peer_key(self, peer_username: str) -> bytes:
        """Fetch peer's ephemeral public key (X25519) from relay."""
        await self._send_json({"type": "get_peer", "username": peer_username})
        msg = await self._recv_json()
        if msg.get("type") == "error":
            raise RuntimeError("get_peer failed: %s", msg.get("message", msg))
        if msg.get("type") != "peer_key":
            raise RuntimeError("get_peer failed: %s", msg)
        raw = msg.get("ephemeral_pub", "")
        padding = "=" * (-len(raw) % 4)
        return base64.urlsafe_b64decode((raw + padding).encode("ascii"))

    async def upload_bundle(self, bundle_dict: Dict[str, Any]) -> None:
        """Upload public PreKey bundle to relay."""
        await self._send_json({"type": "upload_bundle", "username": self.username, "bundle": bundle_dict})
        msg = await self._recv_json()
        if msg.get("type") == "error":
            raise RuntimeError("Bundle upload failed: %s", msg.get("message", msg))
        if msg.get("type") != "bundle_uploaded" and not (
            msg.get("type") == "ok" and msg.get("message") == "bundle_uploaded"
        ):
            raise RuntimeError("Bundle upload failed: %s", msg)

    async def get_peer_bundle(self, peer_username: str) -> Dict[str, Any]:
        """Fetch peer's public PreKey bundle for X3DH."""
        await self._send_json({"type": "get_bundle", "username": peer_username})
        msg = await self._recv_json()
        if msg.get("type") == "error":
            raise RuntimeError("get_bundle failed: %s", msg.get("message", msg))
        if msg.get("type") != "peer_bundle":
            raise RuntimeError("get_bundle failed: %s", msg)
        return msg.get("bundle", {})

    async def send_session_init(
        self,
        to_username: str,
        identity_dh_pub: bytes,
        eph_pub: bytes,
        opk_id_used: Optional[int] = None,
    ) -> None:
        """Send X3DH session init (for offline recipient it is queued on server)."""
        id_b64 = base64.urlsafe_b64encode(identity_dh_pub).decode("ascii").rstrip("=")
        eph_b64 = base64.urlsafe_b64encode(eph_pub).decode("ascii").rstrip("=")
        await self._send_json({
            "type": "session_init",
            "to": to_username,
            "identity_dh_pub": id_b64,
            "eph_pub": eph_b64,
            "opk_id_used": opk_id_used,
        })

    def set_session(self, session: SessionCrypto) -> None:
        """Set legacy session crypto for encrypt/decrypt."""
        self._session = session
        self._double_ratchet = None

    def set_double_ratchet(self, engine: Any) -> None:
        """Set Double Ratchet engine for encrypt/decrypt (takes precedence over session)."""
        self._double_ratchet = engine
        self._session = None

    async def send_message(self, to_username: str, plaintext: bytes) -> None:
        """Encrypt with session or double ratchet and send to peer."""
        if self._double_ratchet is not None:
            wire = self._double_ratchet.ratchet_encrypt(plaintext)
            payload_dict = wire_message_to_dict(wire)
            await self._send_json({
                "type": "msg",
                "to": to_username,
                "payload": json.dumps(payload_dict),
                "format": "double_ratchet",
            })
            return
        if self._session is None:
            raise RuntimeError("No session or double ratchet set")
        payload = self._session.encrypt_message(plaintext)
        b64 = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        await self._send_json({"type": "msg", "to": to_username, "payload": b64})

    async def send_raw(self, to_username: str, payload_b64: str) -> None:
        """Send pre-encoded payload (e.g. already encrypted)."""
        await self._send_json({"type": "msg", "to": to_username, "payload": payload_b64})

    async def _send_json(self, obj: Dict[str, Any]) -> None:
        if self._ws is None:
            raise RuntimeError("Not connected")
        await self._ws.send(json.dumps(obj))

    async def _recv_json(self) -> Dict[str, Any]:
        if self._ws is None:
            raise RuntimeError("Not connected")
        raw = await self._ws.recv()
        return json.loads(raw)

    async def recv_session_init(self) -> Dict[str, Any]:
        """Block until a session_init is received (from peer who ran X3DH as initiator)."""
        return await self._init_queue.get()

    async def recv_message(self) -> tuple[str, bytes]:
        """
        Receive one message from relay. Blocks until available.
        Returns (from_username, plaintext). Decrypts with double ratchet or session.
        """
        msg = await self._recv_queue.get()
        from_user = msg.get("from", "")
        payload_raw = msg.get("payload", "")
        if self._double_ratchet is not None:
            try:
                payload_dict = json.loads(payload_raw)
            except (json.JSONDecodeError, TypeError) as e:
                raise DecryptionError("Invalid double-ratchet payload encoding") from e
            wire = wire_message_from_dict(payload_dict)
            payload = self._double_ratchet.ratchet_decrypt(wire)
            return from_user, payload
        padding = "=" * (-len(payload_raw) % 4)
        payload = base64.urlsafe_b64decode((payload_raw + padding).encode("ascii"))
        if self._session is not None:
            payload = self._session.decrypt_message(payload)
        return from_user, payload

    async def run_receiver(self) -> None:
        """
        Background task: read from WebSocket and put incoming messages into queue.
        """
        if self._ws is None:
            raise RuntimeError("Not connected")
        try:
            while True:
                raw = await self._ws.recv()
                data = json.loads(raw)
                if data.get("type") == "msg":
                    await self._recv_queue.put(data)
                elif data.get("type") == "session_init":
                    await self._init_queue.put(data)
        except Exception as e:
            logger.exception("Receiver stopped: %s", e)
            raise

    async def close(self) -> None:
        if self._ws is not None:
            await self._ws.close()
            self._ws = None

    async def __aenter__(self) -> "GhostChatWebSocketClient":
        await self.connect()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
