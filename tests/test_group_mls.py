from __future__ import annotations

import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from group.epoch_manager import EpochManager
from group.errors import ReplayedGroupMessageError
from group.group_messaging import GroupMessenger
from group.membership import MembershipController
from group.serialization import deserialize_group_state, serialize_group_state
from group.state_verification import summarize_state, verify_consistency


def _rand_id() -> bytes:
    return os.urandom(16)


def test_group_creation_and_serialization_roundtrip() -> None:
    gid = _rand_id()
    a = os.urandom(32)
    b = os.urandom(32)

    controller = MembershipController.create_group(gid, [a, b])
    state = controller.state

    payload = serialize_group_state(state)
    state2 = deserialize_group_state(payload)

    assert state2.group_id == state.group_id
    assert state2.epoch == state.epoch
    assert state2.members.keys() == state.members.keys()
    assert state2.group_secret == state.group_secret
    assert state2.application_key == state.application_key
    assert state2.group_hash == state.group_hash


def test_member_add_rotates_epoch_and_keys() -> None:
    gid = _rand_id()
    a = os.urandom(32)
    b = os.urandom(32)

    controller = MembershipController.create_group(gid, [a, b])
    state_before = controller.state
    epoch_before = state_before.epoch
    app_key_before = state_before.application_key

    c = os.urandom(32)
    controller.add_member(c)
    state_after = controller.state

    assert state_after.epoch == epoch_before + 1
    assert state_after.application_key != app_key_before


def test_member_remove_rotates_epoch_and_keys() -> None:
    gid = _rand_id()
    a = os.urandom(32)
    b = os.urandom(32)

    controller = MembershipController.create_group(gid, [a, b])
    state_before = controller.state
    epoch_before = state_before.epoch
    app_key_before = state_before.application_key

    controller.remove_member(b)
    state_after = controller.state

    assert state_after.epoch == epoch_before + 1
    assert state_after.application_key != app_key_before


def test_group_messaging_encryption_flow_and_replay_rejection() -> None:
    gid = _rand_id()
    a = os.urandom(32)
    b = os.urandom(32)

    controller = MembershipController.create_group(gid, [a, b])
    state = controller.state

    # Build per-member messengers using their leaf indices.
    leaf_a = state.members[a].leaf_index
    leaf_b = state.members[b].leaf_index

    sender_a = GroupMessenger(state, sender_leaf_index=leaf_a)
    receiver_b = GroupMessenger(state, sender_leaf_index=leaf_b)

    msg = sender_a.encrypt(b"group-msg-1")
    pt = receiver_b.decrypt(msg)
    assert pt == b"group-msg-1"

    # Replay of the same message must fail.
    try:
        _ = receiver_b.decrypt(msg)
    except (ValueError, ReplayedGroupMessageError):
        pass
    else:  # pragma: no cover - defensive
        raise AssertionError("Expected replay rejection for duplicate group message")


def test_group_state_verification_with_epoch_manager() -> None:
    gid = _rand_id()
    a = os.urandom(32)
    b = os.urandom(32)

    controller = MembershipController.create_group(gid, [a, b])
    state1 = controller.state
    epoch_mgr = EpochManager()
    epoch_mgr.record(state1)

    summary1 = summarize_state(state1)
    assert verify_consistency(state1, [summary1], previous_epoch=None)
    assert epoch_mgr.verify_state(state1)

    # After membership change, the epoch should increase and the hash should
    # change, and verification should still pass for the new state.
    c = os.urandom(32)
    controller.add_member(c)
    state2 = controller.state
    summary2 = summarize_state(state2)

    assert state2.epoch >= state1.epoch
    assert summary2.group_hash != summary1.group_hash
    assert verify_consistency(state2, [summary2], previous_epoch=state1.epoch)

