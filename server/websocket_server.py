"""
WebSocket relay server for GhostChat.

In-memory registry: username -> websocket, username -> bundle.
Handles register, upload_bundle, get_peer_bundle, session_init, get_peer (legacy), direct_message.
Never closes the socket on unknown or malformed messages; returns JSON errors and keeps connection alive.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

app = FastAPI()

# username -> websocket (connected user)
_connections: Dict[str, WebSocket] = {}
# username -> ephemeral_pub_b64 (legacy get_peer)
_ephemeral_pubs: Dict[str, str] = {}
# username -> public PreKey bundle (dict) for X3DH
_bundles: Dict[str, dict] = {}
# username -> list of pending session_init (offline delivery)
_pending_inits: Dict[str, list] = {}


async def _send_json(websocket: WebSocket, obj: Dict[str, Any]) -> None:
    """Send JSON and await."""
    try:
        await websocket.send_json(obj)
    except Exception as e:
        logger.exception("Send failed: %s", e)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.websocket("/ws")
async def websocket_relay(websocket: WebSocket) -> None:
    await websocket.accept()
    username: str | None = None
    try:
        while True:
            try:
                raw = await websocket.receive_text()
            except Exception as e:
                logger.debug("receive_text: %s", e)
                break

            try:
                data = json.loads(raw)
            except json.JSONDecodeError as e:
                logger.warning("Invalid JSON from client: %s", e)
                await _send_json(websocket, {"type": "error", "message": "invalid json"})
                continue

            if not isinstance(data, dict):
                await _send_json(websocket, {"type": "error", "message": "expected json object"})
                continue

            typ = data.get("type")
            if not isinstance(typ, str):
                await _send_json(websocket, {"type": "error", "message": "missing or invalid type"})
                continue

            try:
                if typ == "register":
                    username = data.get("username")
                    if not username or not isinstance(username, str):
                        await _send_json(websocket, {"type": "error", "message": "missing username"})
                        continue
                    username = username.strip()
                    if not username:
                        await _send_json(websocket, {"type": "error", "message": "empty username"})
                        continue
                    ephemeral_pub = data.get("ephemeral_pub", "") or ""
                    _connections[username] = websocket
                    _ephemeral_pubs[username] = ephemeral_pub if isinstance(ephemeral_pub, str) else ""
                    await _send_json(websocket, {"type": "ok", "message": "registered"})
                    for pending in _pending_inits.pop(username, []):
                        await _send_json(websocket, pending)
                    logger.info("Registered: %s", username)

                elif typ == "upload_bundle":
                    username_b = data.get("username")
                    bundle = data.get("bundle")
                    if not username_b or not isinstance(username_b, str):
                        await _send_json(websocket, {"type": "error", "message": "missing username"})
                        continue
                    username_b = username_b.strip()
                    if not username_b:
                        await _send_json(websocket, {"type": "error", "message": "empty username"})
                        continue
                    if bundle is None or not isinstance(bundle, dict):
                        await _send_json(websocket, {"type": "error", "message": "missing or invalid bundle"})
                        continue
                    _bundles[username_b] = bundle
                    await _send_json(websocket, {"type": "ok", "message": "bundle_uploaded"})
                    logger.info("Bundle uploaded: %s", username_b)

                elif typ == "get_bundle" or typ == "get_peer_bundle":
                    peer = data.get("username") or data.get("peer")
                    if not peer or not isinstance(peer, str):
                        await _send_json(websocket, {"type": "error", "message": "missing peer"})
                        continue
                    peer = peer.strip()
                    if peer not in _bundles:
                        await _send_json(
                            websocket,
                            {"type": "error", "message": "peer not found", "peer": peer},
                        )
                        continue
                    await _send_json(
                        websocket,
                        {"type": "peer_bundle", "peer": peer, "bundle": _bundles[peer]},
                    )

                elif typ == "get_peer":
                    peer = data.get("username") or data.get("peer")
                    if not peer or not isinstance(peer, str):
                        await _send_json(websocket, {"type": "error", "message": "missing peer"})
                        continue
                    peer = peer.strip()
                    if peer not in _connections or peer not in _ephemeral_pubs:
                        await _send_json(
                            websocket,
                            {"type": "error", "message": "peer not found", "peer": peer},
                        )
                        continue
                    await _send_json(
                        websocket,
                        {"type": "peer_key", "ephemeral_pub": _ephemeral_pubs[peer]},
                    )

                elif typ == "session_init":
                    from_user = username
                    to_user = data.get("to")
                    identity_dh_pub = data.get("identity_dh_pub", "")
                    eph_pub = data.get("eph_pub", "")
                    opk_id_used = data.get("opk_id_used")
                    if not from_user:
                        await _send_json(websocket, {"type": "error", "message": "register first"})
                        continue
                    if not to_user or not identity_dh_pub or not eph_pub:
                        await _send_json(websocket, {"type": "error", "message": "missing session_init fields"})
                        continue
                    init_msg = {
                        "type": "session_init",
                        "from": from_user,
                        "identity_dh_pub": identity_dh_pub,
                        "eph_pub": eph_pub,
                        "opk_id_used": opk_id_used,
                    }
                    if to_user in _connections:
                        try:
                            await _send_json(_connections[to_user], init_msg)
                        except Exception as e:
                            logger.warning("Could not deliver session_init to %s: %s", to_user, e)
                            _pending_inits.setdefault(to_user, []).append(init_msg)
                    else:
                        _pending_inits.setdefault(to_user, []).append(init_msg)

                elif typ == "msg" or typ == "direct_message":
                    to_user = data.get("to")
                    payload = data.get("payload", "")
                    if not username:
                        await _send_json(websocket, {"type": "error", "message": "register first"})
                        continue
                    if not to_user or not isinstance(to_user, str):
                        await _send_json(websocket, {"type": "error", "message": "missing 'to'"})
                        continue
                    to_user = to_user.strip()
                    if to_user not in _connections:
                        await _send_json(
                            websocket,
                            {"type": "error", "message": "peer not found", "peer": to_user},
                        )
                        continue
                    try:
                        await _send_json(
                            _connections[to_user],
                            {"type": "msg", "from": username, "payload": payload},
                        )
                    except Exception as e:
                        logger.warning("Could not relay message to %s: %s", to_user, e)
                        await _send_json(
                            websocket,
                            {"type": "error", "message": "delivery failed", "peer": to_user},
                        )

                else:
                    await _send_json(websocket, {"type": "error", "message": "unknown type", "received_type": typ})

            except WebSocketDisconnect:
                raise
            except Exception as e:
                logger.exception("Message handling error: %s", e)
                await _send_json(websocket, {"type": "error", "message": "server error"})

    except WebSocketDisconnect:
        if username and username in _connections:
            del _connections[username]
            if username in _ephemeral_pubs:
                del _ephemeral_pubs[username]
            logger.info("Disconnected: %s", username)
    except Exception as e:
        logger.exception("WebSocket error: %s", e)
        if username and username in _connections:
            del _connections[username]
            if username in _ephemeral_pubs:
                del _ephemeral_pubs[username]
        # Do not call websocket.close() to avoid "no close frame" issues

    return None


if __name__ == "__main__":
    import uvicorn

    host = "127.0.0.1"
    port = 8765
    print(f"GhostChat relay server started on ws://localhost:{port}", flush=True)
    uvicorn.run(app, host=host, port=port)
