from __future__ import annotations

"""
Property tests for the Double Ratchet state machine.

Goals:
- Exercise encrypt/decrypt sequences between two peers under varied
  send patterns and plaintexts.
- Assert key invariants: successful round-trips, single-use message
  keys (replay rejection), basic out-of-order handling, and continuity
  after save/load.

Out of scope:
- Arbitrary internal states that cannot arise from valid protocol
  evolution; all tests start from correctly initialized peers and use
  real encrypt/decrypt calls.
"""

import pathlib
import random
import sys
import tempfile

import pytest

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
except ModuleNotFoundError:  # pragma: no cover - hypothesis is an optional dev dependency
    pytest.skip("hypothesis not installed; skipping fuzz/property tests", allow_module_level=True)

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client.crypto.double_ratchet import DoubleRatchetEngine, create_initial_state
from client.crypto.ratchet_errors import DecryptionError, DuplicateMessageError, SkipDistanceExceededError
from client.crypto.message import wire_message_to_dict, wire_message_from_dict
from client.session_store import load_session, save_session
from tests.strategies import small_bytes


def _make_pair(max_skipped_keys: int = 1000) -> tuple[DoubleRatchetEngine, DoubleRatchetEngine]:
    root_key = b"0" * 32
    alice_state = create_initial_state(root_key, is_initiator=True, max_skipped_keys=max_skipped_keys)
    bob_state = create_initial_state(root_key, is_initiator=False, max_skipped_keys=max_skipped_keys)
    return DoubleRatchetEngine(alice_state), DoubleRatchetEngine(bob_state)


@settings(max_examples=40)
@given(
    who_sends=st.lists(st.sampled_from(["alice", "bob"]), min_size=1, max_size=8),
    payloads=st.lists(small_bytes(min_size=0, max_size=24), min_size=1, max_size=8),
)
def test_property_conversation_roundtrip_and_replay_rejection(
    who_sends: list[str],
    payloads: list[bytes],
) -> None:
    """
    Property: for a short random sequence of sends between Alice and Bob,
    - every message decrypts correctly exactly once, and
    - replays of any delivered message are rejected.
    """
    alice, bob = _make_pair()
    wires = []

    for sender_name, payload in zip(who_sends, payloads):
        sender = alice if sender_name == "alice" else bob
        receiver = bob if sender_name == "alice" else alice
        wire = sender.ratchet_encrypt(payload)
        got = receiver.ratchet_decrypt(wire)
        assert got == payload
        wires.append((receiver, wire))

    # Replaying any delivered message must fail.
    for receiver, wire in wires:
        with pytest.raises(DuplicateMessageError):
            receiver.ratchet_decrypt(wire)


@settings(max_examples=30)
@given(
    payloads=st.lists(small_bytes(min_size=0, max_size=24), min_size=3, max_size=6),
)
def test_property_out_of_order_within_window(payloads: list[bytes]) -> None:
    """
    Property: out-of-order delivery within the skipped-key window and skip distance
    still decrypts each message exactly once, and replays are rejected.
    """
    alice, bob = _make_pair()
    wires = [alice.ratchet_encrypt(p) for p in payloads]

    # Deliver a shuffled order but keep it within a small range (no large gaps).
    order = list(range(len(wires)))
    random.shuffle(order)

    seen = {}
    for idx in order:
        wire = wires[idx]
        got = bob.ratchet_decrypt(wire)
        seen[idx] = got

    # All payloads delivered exactly once.
    assert len(seen) == len(payloads)
    for idx, pt in seen.items():
        assert pt == payloads[idx]

    # Replays fail.
    for wire in wires:
        with pytest.raises(DuplicateMessageError):
            bob.ratchet_decrypt(wire)


@settings(max_examples=20)
@given(
    gap=st.integers(min_value=5001, max_value=6000),
    payload=small_bytes(min_size=0, max_size=24),
)
def test_property_skip_distance_limit_enforced(gap: int, payload: bytes) -> None:
    """
    Property: messages that exceed the configured skip distance relative to Nr
    are rejected with SkipDistanceExceededError or DecryptionError.
    """
    alice, bob = _make_pair()

    # Force Bob to advance his receiving chain a bit with one message.
    first = alice.ratchet_encrypt(b"warmup")
    assert bob.ratchet_decrypt(first) == b"warmup"

    # Now artificially construct a header far ahead; easiest is to encrypt
    # 'gap' messages and then try to decrypt the last, which yields a large gap.
    wires = [alice.ratchet_encrypt(payload) for _ in range(gap)]
    target = wires[-1]
    with pytest.raises((SkipDistanceExceededError, DecryptionError)):
        bob.ratchet_decrypt(target)


@settings(max_examples=20)
@given(
    msgs=st.lists(small_bytes(min_size=0, max_size=24), min_size=1, max_size=5),
)
def test_property_save_load_continuity_and_replay_after_restore(msgs: list[bytes]) -> None:
    """
    Property: after a short conversation and a save/load cycle, the next
    message decrypts correctly, and replays before and after restore are
    still rejected.
    """
    alice, bob = _make_pair()
    wires = []
    for m in msgs:
        w = alice.ratchet_encrypt(m)
        assert bob.ratchet_decrypt(w) == m
        wires.append(w)

    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        save_session("alice", "bob", alice.state, base_dir=base)
        save_session("bob", "alice", bob.state, base_dir=base)
        alice_loaded = load_session("alice", "bob", base_dir=base)
        bob_loaded = load_session("bob", "alice", base_dir=base)
    assert alice_loaded is not None and bob_loaded is not None

    alice_restored = DoubleRatchetEngine(alice_loaded)
    bob_restored = DoubleRatchetEngine(bob_loaded)

    # Replaying an old wire after restore must still fail.
    for w in wires:
        with pytest.raises(DuplicateMessageError):
            bob_restored.ratchet_decrypt(w)

    # New message after restore still decrypts.
    w_new = alice_restored.ratchet_encrypt(b"after-restore")
    assert bob_restored.ratchet_decrypt(w_new) == b"after-restore"


@settings(max_examples=25)
@given(payload=small_bytes(min_size=1, max_size=24))
def test_property_aad_and_ciphertext_tampering_fail_closed(payload: bytes) -> None:
    """
    Property: tampering with header fields, nonce, or ciphertext never
    yields a valid plaintext; decrypt either raises DecryptionError or
    DuplicateMessageError.
    """
    alice, bob = _make_pair()
    wire = alice.ratchet_encrypt(payload)

    variants = []
    # Tamper n
    tampered_n = wire_message_from_dict(wire_message_to_dict(wire))
    tampered_n.header.n += 1
    variants.append(tampered_n)
    # Tamper pn
    tampered_pn = wire_message_from_dict(wire_message_to_dict(wire))
    tampered_pn.header.pn += 1
    variants.append(tampered_pn)
    # Tamper dh
    tampered_dh = wire_message_from_dict(wire_message_to_dict(wire))
    hd = bytearray(tampered_dh.header.dh)
    hd[0] ^= 0xFF
    tampered_dh.header.dh = bytes(hd)
    variants.append(tampered_dh)
    # Tamper nonce
    tampered_nonce = wire_message_from_dict(wire_message_to_dict(wire))
    nn = bytearray(tampered_nonce.nonce)
    nn[0] ^= 0x01
    tampered_nonce.nonce = bytes(nn)
    variants.append(tampered_nonce)
    # Tamper ciphertext
    tampered_ct = wire_message_from_dict(wire_message_to_dict(wire))
    ct = bytearray(tampered_ct.ciphertext)
    ct[0] ^= 0x01
    tampered_ct.ciphertext = bytes(ct)
    variants.append(tampered_ct)

    for v in variants:
        with pytest.raises((DecryptionError, DuplicateMessageError)):
            bob.ratchet_decrypt(v)

