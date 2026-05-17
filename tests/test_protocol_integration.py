from __future__ import annotations

import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nacl.public import PrivateKey as X25519PrivateKey

from client.message_api import (
    register_endpoint,
    send_text,
    recv_text,
    recv_sealed,
    get_pending_cover_packets,
    _endpoints,
)
from client.session_manager import SessionManager
from protocol.envelope import ProtocolEnvelope
from protocol.session_reset import SessionResetState
from server.router import Router
from network.mix_router import MixConfig, MixRouter
from network.cover_traffic import CoverTrafficConfig, CoverTrafficScheduler
from network.dummy_packets import make_dummy_sealed_envelope


def _linked_managers() -> tuple[SessionManager, SessionManager, bytes, bytes]:
    """
    Build two SessionManagers with a symmetric double-ratchet setup for tests.
    """

    root_key = os.urandom(32)
    alice_mgr = SessionManager(profile="alice")
    bob_mgr = SessionManager(profile="bob")

    # Symmetric DH setup similar to earlier ratchet tests.
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


def test_protocol_integration_end_to_end() -> None:
    alice_mgr, bob_mgr, peer_id, _ = _linked_managers()
    register_endpoint("alice", alice_mgr)
    register_endpoint("bob", bob_mgr)

    send_text("alice", "bob", peer_id, "hello bob")
    msgs = recv_text("bob", peer_id)
    assert msgs == ["hello bob"]


def test_protocol_integration_replay_triggers_reset() -> None:
    alice_mgr, bob_mgr, peer_id, _ = _linked_managers()
    register_endpoint("alice", alice_mgr)
    register_endpoint("bob", bob_mgr)

    # Send once.
    send_text("alice", "bob", peer_id, "hi")
    # Manually replay the same envelope from Bob's inbox.
    bob_endpoint = _endpoints["bob"]
    assert len(bob_endpoint.inbox) == 1
    env = bob_endpoint.inbox[0]

    # First decrypt should succeed.
    msgs = recv_text("bob", peer_id)
    assert msgs == ["hi"]

    # Replay: reinsert the same envelope.
    bob_endpoint.inbox.append(env)

    try:
        _ = recv_text("bob", peer_id)
    except ValueError:
        # Ensure the session is marked for reset.
        ctx = bob_mgr._sessions[peer_id]
        assert isinstance(ctx.reset_state, SessionResetState)
        assert ctx.reset_state.needs_reset
    else:  # pragma: no cover - defensive
        raise AssertionError("Expected replay to trigger reset and error")


def test_end_to_end_via_relay_router() -> None:
    """
    Minimal end-to-end flow:
      - Alice and Bob have a session.
      - Alice encrypts to a ProtocolEnvelope.
      - Relay Router enqueues/dequeues the envelope dict.
      - Bob parses, applies replay/fork checks, and decrypts.
    """

    alice_mgr, bob_mgr, peer_id, _ = _linked_managers()

    # Alice encrypts a message.
    env = alice_mgr.encrypt_for(peer_id, b"hello via relay")
    env_dict = env.to_dict()

    # Relay routes the JSON-like envelope.
    router = Router()
    router.enqueue("bob", env_dict)

    # Bob receives from the relay and decrypts.
    incoming = router.dequeue_all("bob")
    assert len(incoming) == 1
    received_env = ProtocolEnvelope.from_dict(incoming[0])
    plaintext = bob_mgr.decrypt_from(peer_id, received_env)
    assert plaintext == b"hello via relay"


def test_tampered_envelope_does_not_burn_replay_or_ratchet_state() -> None:
    alice_mgr, bob_mgr, peer_id, _ = _linked_managers()
    env = alice_mgr.encrypt_for(peer_id, b"authenticated")
    bad_ct = bytearray(env.ciphertext)
    bad_ct[0] ^= 0x01
    tampered = ProtocolEnvelope(
        version=env.version,
        session_id=env.session_id,
        sender_ratchet_key=env.sender_ratchet_key,
        message_number=env.message_number,
        previous_chain_length=env.previous_chain_length,
        ciphertext=bytes(bad_ct),
        nonce=env.nonce,
        meta=env.meta,
    )

    with pytest.raises(Exception):
        bob_mgr.decrypt_from(peer_id, tampered)

    assert bob_mgr.decrypt_from(peer_id, env) == b"authenticated"


def test_sealed_sender_via_relay_router() -> None:
    """
    Sealed sender flow through relay: outer envelope has only recipient_locator
    and opaque sp; Bob recovers sender from inner and decrypts.
    """
    alice_mgr, bob_mgr, peer_id, _ = _linked_managers()
    outer = alice_mgr.encrypt_sealed(
        peer_id, b"hello sealed via relay", recipient_locator="bob"
    )
    assert "recipient_locator" in outer
    assert "sp" in outer
    assert "sender_id" not in outer

    router = Router()
    router.enqueue(outer["recipient_locator"], outer)

    incoming = router.dequeue_all("bob")
    assert len(incoming) == 1
    recv_peer_id, plaintext = bob_mgr.decrypt_sealed(incoming[0])
    assert recv_peer_id == peer_id
    assert plaintext == b"hello sealed via relay"


def test_sealed_sender_and_plain_both_work() -> None:
    """Sealed and non-sealed paths can coexist; validation applies to both."""
    alice_mgr, bob_mgr, peer_id, _ = _linked_managers()
    register_endpoint("alice", alice_mgr)
    register_endpoint("bob", bob_mgr)

    send_text("alice", "bob", peer_id, "plain", sealed_sender=False)
    send_text("alice", "bob", peer_id, "sealed", sealed_sender=True)

    plain_msgs = recv_text("bob", peer_id)
    assert plain_msgs == ["plain"]
    sealed_msgs = recv_sealed("bob")
    assert len(sealed_msgs) == 1
    assert sealed_msgs[0][1] == "sealed"


def test_delayed_routing_delivers_sealed_sender_message() -> None:
    """With mix delay enabled, message is delivered after deliver_due(now)."""
    alice_mgr, bob_mgr, peer_id, _ = _linked_managers()
    mix = MixRouter(MixConfig(deterministic_mode=True, fixed_delay_sec=0.0))
    router = Router(mix_router=mix)

    outer = alice_mgr.encrypt_sealed(
        peer_id, b"delayed hello", recipient_locator="bob"
    )
    router.enqueue_by_envelope(outer, use_mix=True, now=1000.0)
    assert len(router.dequeue_all("bob")) == 0
    router.deliver_due(now=1000.0)
    incoming = router.dequeue_all("bob")
    assert len(incoming) == 1
    recv_peer_id, plaintext = bob_mgr.decrypt_sealed(incoming[0])
    assert recv_peer_id == peer_id
    assert plaintext == b"delayed hello"


def test_mixed_real_dummy_cover_does_not_break_flow() -> None:
    """Real + dummy + cover traffic: only real message is decrypted."""
    alice_mgr, bob_mgr, peer_id, _ = _linked_managers()
    register_endpoint("alice", alice_mgr)
    register_endpoint("bob", bob_mgr)

    send_text("alice", "bob", peer_id, "real msg", sealed_sender=True)
    _endpoints["bob"].inbox.append(make_dummy_sealed_envelope("bob").envelope)

    cover_cfg = CoverTrafficConfig(
        enabled=True,
        deterministic_mode=True,
        deterministic_interval_sec=0.0,
        recipient_locator="bob",
    )
    sched = CoverTrafficScheduler(cover_cfg)
    cover_list = get_pending_cover_packets(sched, now=100.0)
    for env in cover_list:
        _endpoints["bob"].inbox.append(env)

    msgs = recv_sealed("bob", drop_undecryptable=True)
    assert len(msgs) == 1
    assert msgs[0][1] == "real msg"


def test_relay_remains_sender_blind_with_delayed_dummy() -> None:
    """Router only sees recipient_locator; no sender in envelope."""
    alice_mgr, bob_mgr, peer_id, _ = _linked_managers()
    mix = MixRouter(MixConfig(deterministic_mode=True, fixed_delay_sec=0.0))
    router = Router(mix_router=mix)

    real = alice_mgr.encrypt_sealed(peer_id, b"x", recipient_locator="bob")
    dummy = make_dummy_sealed_envelope("bob").envelope

    router.enqueue_by_envelope(real, use_mix=True, now=0.0)
    router.enqueue_by_envelope(dummy, use_mix=True, now=0.0)
    router.deliver_due(now=1.0)

    for key in ["sender_id", "sid"]:
        assert key not in real
        assert key not in dummy
    bob_msgs = router.dequeue_all("bob")
    assert len(bob_msgs) == 2


