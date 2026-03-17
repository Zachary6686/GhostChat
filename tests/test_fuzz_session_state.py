from __future__ import annotations

"""
Property tests for session persistence and state serialization.

Goals:
- Ensure state_to_dict / state_from_dict round-trip preserves all
  security-relevant fields for valid states.
- Ensure corrupted or partially mutated persisted state fails closed
  (CorruptedSessionError) instead of being partially recovered.
- Exercise save_session / load_session under small random conversations.

Out of scope:
- Generating arbitrary impossible internal states; we only mutate states
  that first arise from valid protocol operations.
"""

import pathlib
import sys
import tempfile
from copy import deepcopy

import pytest

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
except ModuleNotFoundError:  # pragma: no cover - hypothesis is an optional dev dependency
    pytest.skip("hypothesis not installed; skipping fuzz/property tests", allow_module_level=True)

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client.crypto.double_ratchet import DoubleRatchetEngine, DoubleRatchetState, create_initial_state
from client.crypto.ratchet_errors import CorruptedSessionError, SessionRollbackError
from client.session_store import load_session, save_session, state_from_dict, state_to_dict
from tests.strategies import small_bytes


def _make_pair() -> tuple[DoubleRatchetEngine, DoubleRatchetEngine]:
    root_key = b"0" * 32
    alice_state = create_initial_state(root_key, is_initiator=True)
    bob_state = create_initial_state(root_key, is_initiator=False)
    return DoubleRatchetEngine(alice_state), DoubleRatchetEngine(bob_state)


@settings(max_examples=40)
@given(
    msgs_a=st.lists(small_bytes(min_size=0, max_size=16), min_size=0, max_size=5),
    msgs_b=st.lists(small_bytes(min_size=0, max_size=16), min_size=0, max_size=5),
)
def test_state_roundtrip_preserves_fields_after_conversation(msgs_a: list[bytes], msgs_b: list[bytes]) -> None:
    """
    After a small conversation, state_to_dict/state_from_dict round-trip
    preserves core fields and allows continued messaging.
    """
    alice, bob = _make_pair()

    # Conversation: Alice sends all her msgs, then Bob sends his.
    for m in msgs_a:
        wire = alice.ratchet_encrypt(m)
        got = bob.ratchet_decrypt(wire)
        assert got == m
    for m in msgs_b:
        wire = bob.ratchet_encrypt(m)
        got = alice.ratchet_decrypt(wire)
        assert got == m

    # Round-trip Alice's state.
    orig: DoubleRatchetState = alice.state
    d = state_to_dict(orig)
    rt = state_from_dict(deepcopy(d))
    assert rt.root_key == orig.root_key
    assert rt.dhs_private == orig.dhs_private
    assert rt.dhr == orig.dhr
    assert rt.Ns == orig.Ns
    assert rt.Nr == orig.Nr
    assert rt.PN == orig.PN
    assert rt.session_version == orig.session_version

    # Use restored state to send another message to Bob.
    restored_engine = DoubleRatchetEngine(rt)
    wire2 = restored_engine.ratchet_encrypt(b"after-restore")
    assert bob.ratchet_decrypt(wire2) == b"after-restore"


@settings(max_examples=40)
@given(
    mutate_key=st.sampled_from(
        [
            "root_key",
            "sending_chain_key",
            "receiving_chain_key",
            "dhs_private",
            "dhr",
            "Ns",
            "Nr",
            "PN",
            "skipped",
            "received_ids",
            "session_version",
        ]
    )
)
def test_mutated_persisted_state_fails_closed(mutate_key: str) -> None:
    """
    Mutating a single field in a valid serialized state should cause
    state_from_dict to raise CorruptedSessionError (or equivalent),
    rather than silently accepting a partially invalid structure.
    """
    alice, _ = _make_pair()
    d = state_to_dict(alice.state)
    mutated = deepcopy(d)

    if mutate_key in {"root_key", "sending_chain_key", "receiving_chain_key", "dhs_private", "dhr"}:
        mutated[mutate_key] = "!!!invalid-base64!!!"
    elif mutate_key in {"Ns", "Nr", "PN", "session_version"}:
        mutated[mutate_key] = "not-an-int"
    elif mutate_key == "skipped":
        mutated["skipped"] = {"bad-key": "bad-value"}
    elif mutate_key == "received_ids":
        mutated["received_ids"] = {"ids": ["too-short"]}

    with pytest.raises(CorruptedSessionError):
        state_from_dict(mutated)


@settings(max_examples=20)
@given(
    msgs=st.lists(small_bytes(min_size=0, max_size=16), min_size=0, max_size=5),
)
def test_save_load_roundtrip_and_rollback_property(msgs: list[bytes]) -> None:
    """
    Property: save_session/load_session round-trip yields a usable session,
    and anti-rollback still triggers when attempting to save an older state.
    """
    alice, bob = _make_pair()

    for m in msgs:
        w = alice.ratchet_encrypt(m)
        assert bob.ratchet_decrypt(w) == m

    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        # First save.
        save_session("alice", "bob", alice.state, base_dir=base)
        v1 = alice.state.session_version

        # Load and continue.
        loaded = load_session("alice", "bob", base_dir=base)
        assert loaded is not None
        assert loaded.session_version == v1
        engine_loaded = DoubleRatchetEngine(loaded)
        w2 = engine_loaded.ratchet_encrypt(b"continuation")
        assert bob.ratchet_decrypt(w2) == b"continuation"

        # Attempt rollback: artificially decrease session_version and try to save.
        loaded.session_version = 1
        with pytest.raises(SessionRollbackError):
            save_session("alice", "bob", loaded, base_dir=base)

