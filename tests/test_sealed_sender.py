from __future__ import annotations

import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nacl.public import PrivateKey as X25519PrivateKey

from client.message_api import (
    register_endpoint,
    send_text,
    recv_text,
    recv_sealed,
    _endpoints,
)
from client.session_manager import SessionManager
from protocol.sealed_sender import (
    SealedOuterEnvelope,
    seal,
    unseal,
    derive_sealing_key,
    is_sealed_envelope,
    SEALED_SENDER_VERSION,
)
from protocol.message_format import InnerSenderPackage
from protocol.session_reset import SessionResetState
from server.router import Router, get_routing_recipient


def _linked_managers() -> tuple[SessionManager, SessionManager, bytes, bytes]:
    root_key = os.urandom(32)
    alice_mgr = SessionManager(profile="alice")
    bob_mgr = SessionManager(profile="bob")
    alice_dh = X25519PrivateKey.generate()
    bob_dh = X25519PrivateKey.generate()
    peer_id = b"peer"
    alice_mgr.create_symmetric_session(
        peer_id=peer_id,
        root_key=root_key,
        dhs=alice_dh,
        dhr=bytes(bob_dh.public_key),
        is_initiator=True,
    )
    bob_mgr.create_symmetric_session(
        peer_id=peer_id,
        root_key=root_key,
        dhs=bob_dh,
        dhr=bytes(alice_dh.public_key),
        is_initiator=False,
    )
    return alice_mgr, bob_mgr, peer_id, root_key


def test_sealed_sender_alice_to_bob_via_in_memory() -> None:
    """Successful sealed sender flow: Alice -> Bob, relay routes by recipient only."""
    alice_mgr, bob_mgr, peer_id, _ = _linked_managers()
    register_endpoint("alice", alice_mgr)
    register_endpoint("bob", bob_mgr)

    send_text("alice", "bob", peer_id, "hello sealed", sealed_sender=True)
    msgs = recv_sealed("bob")
    assert len(msgs) == 1
    recv_peer_id, plaintext = msgs[0]
    assert recv_peer_id == peer_id
    assert plaintext == "hello sealed"


def test_relay_cannot_see_sender_identity() -> None:
    """Outer envelope has no plaintext sender; routing uses recipient_locator only."""
    alice_mgr, bob_mgr, peer_id, _ = _linked_managers()
    outer = alice_mgr.encrypt_sealed(
        peer_id, b"secret", recipient_locator="bob", ttl=60
    )
    assert "recipient_locator" in outer
    assert outer["recipient_locator"] == "bob"
    assert "sp" in outer  # sealed payload (opaque)
    assert "sender_id" not in outer
    assert "sid" not in outer or outer.get("sid") == ""  # no plaintext session id
    recipient = get_routing_recipient(outer)
    assert recipient == "bob"


def test_malformed_sealed_package_rejected() -> None:
    """Invalid or truncated sealed payload raises on parse or unseal."""
    from protocol.sealed_sender import SealedOuterEnvelope

    # Too short sealed payload
    outer_dict = {
        "v": SEALED_SENDER_VERSION,
        "recipient_locator": "bob",
        "ttl": 60,
        "sp": "YQ==",  # minimal b64, decodes to 1 byte
        "pad": "",
    }
    try:
        env = SealedOuterEnvelope.from_dict(outer_dict)
        assert False, "expected ValueError"
    except ValueError as e:
        assert "short" in str(e).lower() or "invalid" in str(e).lower()

    # Missing recipient_locator
    bad = {"v": 1, "ttl": 60, "sp": "dGVzdA=="}
    try:
        SealedOuterEnvelope.from_dict(bad)
        assert False
    except ValueError as e:
        assert "recipient" in str(e).lower()


def test_replayed_sealed_message_rejected() -> None:
    """Replayed sealed sender message triggers replay rejection and reset."""
    alice_mgr, bob_mgr, peer_id, _ = _linked_managers()
    register_endpoint("alice", alice_mgr)
    register_endpoint("bob", bob_mgr)

    send_text("alice", "bob", peer_id, "once", sealed_sender=True)
    bob_endpoint = _endpoints["bob"]
    assert len(bob_endpoint.inbox) == 1
    sealed_dict = bob_endpoint.inbox[0]

    first = recv_sealed("bob")
    assert len(first) == 1
    assert first[0][1] == "once"

    bob_endpoint.inbox.append(sealed_dict)
    try:
        recv_sealed("bob")
        assert False, "expected replay to raise"
    except ValueError as e:
        assert "replay" in str(e).lower() or "stale" in str(e).lower()

    ctx = bob_mgr._sessions[peer_id]
    assert ctx.reset_state.needs_reset


def test_sealed_sender_multiple_messages_advances_ratchet() -> None:
    """Multiple sealed messages advance message numbers and ratchet state."""
    alice_mgr, bob_mgr, peer_id, _ = _linked_managers()
    register_endpoint("alice", alice_mgr)
    register_endpoint("bob", bob_mgr)

    for i in range(3):
        send_text("alice", "bob", peer_id, f"msg{i}", sealed_sender=True)

    out = recv_sealed("bob")
    assert len(out) == 3
    assert [t[1] for t in out] == ["msg0", "msg1", "msg2"]


def test_sealed_via_relay_router() -> None:
    """Sealed sender flow through relay: enqueue_by_envelope routes by recipient only."""
    alice_mgr, bob_mgr, peer_id, _ = _linked_managers()
    outer = alice_mgr.encrypt_sealed(
        peer_id, b"via relay sealed", recipient_locator="bob"
    )
    router = Router()
    router.enqueue_by_envelope(outer)

    incoming = router.dequeue_all("bob")
    assert len(incoming) == 1
    peer_id_recv, plaintext = bob_mgr.decrypt_sealed(incoming[0])
    assert peer_id_recv == peer_id
    assert plaintext == b"via relay sealed"


def test_is_sealed_envelope() -> None:
    """Helper correctly identifies sealed vs non-sealed envelope dicts."""
    assert is_sealed_envelope({"sp": "x", "recipient_locator": "bob"}) is True
    assert is_sealed_envelope({"sid": "x", "rk": "y"}) is False
    assert is_sealed_envelope({}) is False
