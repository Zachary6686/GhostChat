from __future__ import annotations

import pathlib
import sys

from fastapi.testclient import TestClient

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.websocket_server import (
    _bundles,
    _connections,
    _ephemeral_pubs,
    _pending_inits,
    app,
)  # noqa: E402


def _clear_server_state() -> None:
    _connections.clear()
    _ephemeral_pubs.clear()
    _bundles.clear()
    _pending_inits.clear()


def test_bundle_upload_requires_registered_matching_username() -> None:
    _clear_server_state()
    client = TestClient(app)

    with client.websocket_connect("/ws") as ws:
        ws.send_json({"type": "register", "username": "attacker"})
        assert ws.receive_json()["type"] == "ok"

        ws.send_json(
            {"type": "upload_bundle", "username": "victim", "bundle": {"ik": "evil"}}
        )
        response = ws.receive_json()

        assert response["type"] == "error"
        assert response["message"] == "username mismatch"
        assert "victim" not in _bundles

        ws.send_json(
            {"type": "upload_bundle", "username": "attacker", "bundle": {"ik": "mine"}}
        )
        assert ws.receive_json()["type"] == "ok"
        assert _bundles["attacker"] == {"ik": "mine"}

