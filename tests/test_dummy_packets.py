from __future__ import annotations

import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nacl.public import PrivateKey as X25519PrivateKey

from client.message_api import register_endpoint, send_text, recv_sealed, _endpoints
from client.session_manager import SessionManager
from network.dummy_packets import (
    DummyPacket,
    make_dummy_envelope_like,
    make_dummy_sealed_envelope,
)
from protocol.sealed_sender import make_dummy_sealed_outer, is_sealed_envelope
from server.router import Router, get_routing_recipient


def _linked_managers():
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
    return alice_mgr, bob_mgr, peer_id


def test_dummy_sealed_outer_shape() -> None:
    outer = make_dummy_sealed_outer("bob", ttl=0)
    assert "v" in outer and "recipient_locator" in outer and "sp" in outer
    assert outer["recipient_locator"] == "bob"
    assert get_routing_recipient(outer) == "bob"
    assert is_sealed_envelope(outer)


def test_dummy_sealed_envelope_routed_and_dropped() -> None:
    """Dummy packet is routed by relay; recipient drops it (decrypt fails)."""
    alice_mgr, bob_mgr, peer_id = _linked_managers()
    register_endpoint("alice", alice_mgr)
    register_endpoint("bob", bob_mgr)

    send_text("alice", "bob", peer_id, "real", sealed_sender=True)
    dummy = make_dummy_sealed_envelope("bob", ttl=0)
    _endpoints["bob"].inbox.append(dummy.envelope)

    msgs = recv_sealed("bob", drop_undecryptable=True)
    assert len(msgs) == 1
    assert msgs[0][1] == "real"
    # Dummy was dropped (no second message, no exception)


def test_dummy_packets_do_not_affect_real_sessions() -> None:
    """Multiple dummies + one real: only real is decrypted."""
    alice_mgr, bob_mgr, peer_id = _linked_managers()
    register_endpoint("alice", alice_mgr)
    register_endpoint("bob", bob_mgr)

    for _ in range(3):
        _endpoints["bob"].inbox.append(make_dummy_sealed_envelope("bob").envelope)
    send_text("alice", "bob", peer_id, "only real", sealed_sender=True)
    _endpoints["bob"].inbox.append(make_dummy_sealed_envelope("bob").envelope)

    msgs = recv_sealed("bob", drop_undecryptable=True)
    assert len(msgs) == 1
    assert msgs[0][1] == "only real"


def test_dummy_envelope_like_sealed() -> None:
    real = {"recipient_locator": "bob", "ttl": 60, "sp": "YQ==" * 20, "v": 1, "pad": ""}
    dummy = make_dummy_envelope_like(real)
    assert dummy.is_dummy
    assert dummy.envelope["recipient_locator"] == "bob"
    assert dummy.envelope["ttl"] == 0
    assert dummy.envelope["sp"] != real["sp"]
