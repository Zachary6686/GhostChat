from __future__ import annotations

import os
import pathlib
import sys

import pytest
from cryptography.exceptions import InvalidTag

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client.message_api import (
    register_endpoint,
    send_group_text,
    recv_group_text,
    _endpoints,
)
from client.group_manager import GroupManager
from client.session_manager import SessionManager
from group.membership import MembershipController
from group.group_messaging import GroupMessage, GroupMessenger
from group.errors import EpochMismatchError, ReplayedGroupMessageError
from group.state_verification import (
    validate_local_state,
    validate_serialized,
    validate_incoming_state,
    summarize_state,
    ValidationResult,
)


def _rand_id() -> bytes:
    return os.urandom(16)


def test_create_group_alice_bob_charlie() -> None:
    """Create a group with Alice, Bob, Charlie successfully."""
    gid = _rand_id()
    alice_pk = os.urandom(32)
    bob_pk = os.urandom(32)
    charlie_pk = os.urandom(32)

    controller = MembershipController.create_group(
        gid, [alice_pk, bob_pk, charlie_pk]
    )
    state = controller.state
    assert state.epoch >= 1
    assert len(state.members) == 3
    assert state.group_id == gid
    assert state.application_key is not None
    assert state.group_hash is not None


def test_send_valid_group_message_decrypt_at_recipients() -> None:
    """Send a valid group message and decrypt successfully at recipients."""
    gid = _rand_id()
    a, b = os.urandom(32), os.urandom(32)
    controller = MembershipController.create_group(gid, [a, b])
    state = controller.state
    leaf_a = state.members[a].leaf_index
    leaf_b = state.members[b].leaf_index

    alice_mgr = GroupManager(a)
    alice_mgr.set_state(gid, controller, leaf_a)
    bob_mgr = GroupManager(b)
    bob_mgr.join_group(gid, state, leaf_b)

    register_endpoint("alice", SessionManager("alice"), alice_mgr)
    register_endpoint("bob", SessionManager("bob"), bob_mgr)

    send_group_text("alice", gid, "hello group", member_profiles=["alice", "bob"])
    msgs = recv_group_text("bob", gid)
    assert msgs == ["hello group"]


def test_send_group_text_preserves_sender_counter_between_calls() -> None:
    """High-level group sends must not reuse counter 0 under one epoch key."""
    gid = _rand_id()
    a, b = os.urandom(32), os.urandom(32)
    controller = MembershipController.create_group(gid, [a, b])
    state = controller.state
    leaf_a = state.members[a].leaf_index
    leaf_b = state.members[b].leaf_index

    alice_mgr = GroupManager(a)
    alice_mgr.set_state(gid, controller, leaf_a)
    bob_mgr = GroupManager(b)
    bob_mgr.join_group(gid, state, leaf_b)

    register_endpoint("alice-multi", SessionManager("alice-multi"), alice_mgr)
    register_endpoint("bob-multi", SessionManager("bob-multi"), bob_mgr)

    send_group_text("alice-multi", gid, "first", member_profiles=["bob-multi"])
    send_group_text("alice-multi", gid, "second", member_profiles=["bob-multi"])

    inbox = _endpoints["bob-multi"].group_inbox[gid]
    counters = [GroupMessage.from_dict(envelope["group_message"]).header.counter for envelope in inbox]
    assert counters == [0, 1]
    assert recv_group_text("bob-multi", gid) == ["first", "second"]


def test_add_dave_epoch_rotates_dave_cannot_decrypt_prior() -> None:
    """Add Dave; epoch rotates; Dave cannot decrypt prior-epoch traffic."""
    gid = _rand_id()
    a, b, c = os.urandom(32), os.urandom(32), os.urandom(32)
    controller = MembershipController.create_group(gid, [a, b, c])
    state_before = controller.state
    leaf_a = state_before.members[a].leaf_index

    sender = GroupMessenger(state_before, sender_leaf_index=leaf_a)
    msg_prior = sender.encrypt(b"before dave")

    dave = os.urandom(32)
    controller.add_member(dave)
    state_after = controller.state
    leaf_dave = state_after.members[dave].leaf_index
    receiver_dave = GroupMessenger(state_after, sender_leaf_index=leaf_dave)

    try:
        receiver_dave.decrypt(msg_prior)
        assert False, "Dave should not decrypt prior-epoch message"
    except EpochMismatchError:
        pass


def test_remove_charlie_epoch_rotates_charlie_cannot_decrypt_future() -> None:
    """Remove Charlie; epoch rotates; Charlie cannot decrypt future traffic."""
    gid = _rand_id()
    a, b, charlie = os.urandom(32), os.urandom(32), os.urandom(32)
    controller = MembershipController.create_group(gid, [a, b, charlie])
    state_before = controller.state
    charlie_leaf = state_before.members[charlie].leaf_index
    state_charlie = type(controller.state)(
        group_id=controller.state.group_id,
        epoch=controller.state.epoch,
        tree=controller.state.tree,
        members=controller.state.members.copy(),
        group_secret=controller.state.group_secret,
        application_key=controller.state.application_key,
        group_hash=controller.state.group_hash,
    )
    ratchet_charlie = GroupMessenger(state_charlie, sender_leaf_index=charlie_leaf)

    controller.remove_member(charlie)
    state_after = controller.state
    leaf_a = state_after.members[a].leaf_index
    ratchet_after = GroupMessenger(state_after, sender_leaf_index=leaf_a)
    msg_after = ratchet_after.encrypt(b"after charlie left")

    try:
        ratchet_charlie.decrypt(msg_after)
        assert False, "Charlie should not decrypt future message"
    except EpochMismatchError:
        pass


def test_stale_epoch_group_message_rejected() -> None:
    """Stale epoch group message is rejected."""
    gid = _rand_id()
    a, b = os.urandom(32), os.urandom(32)
    controller = MembershipController.create_group(gid, [a, b])
    state = controller.state
    leaf_a = state.members[a].leaf_index
    leaf_b = state.members[b].leaf_index

    sender = GroupMessenger(state, sender_leaf_index=leaf_a)
    msg = sender.encrypt(b"x")
    controller.add_member(os.urandom(32))
    state_new = controller.state
    receiver = GroupMessenger(state_new, sender_leaf_index=leaf_b)

    try:
        receiver.decrypt(msg)
        assert False, "Stale epoch should be rejected"
    except EpochMismatchError:
        pass


def test_duplicate_replayed_group_message_rejected() -> None:
    """Duplicate/replayed group message is rejected."""
    gid = _rand_id()
    a, b = os.urandom(32), os.urandom(32)
    controller = MembershipController.create_group(gid, [a, b])
    state = controller.state
    leaf_a = state.members[a].leaf_index
    leaf_b = state.members[b].leaf_index

    sender = GroupMessenger(state, sender_leaf_index=leaf_a)
    receiver = GroupMessenger(state, sender_leaf_index=leaf_b)
    msg = sender.encrypt(b"once")
    receiver.decrypt(msg)
    try:
        receiver.decrypt(msg)
        assert False, "Replay should be rejected"
    except ReplayedGroupMessageError:
        pass


def test_tampered_group_message_does_not_poison_replay_cache() -> None:
    """Replay counters are marked only after AEAD authentication succeeds."""
    gid = _rand_id()
    a, b = os.urandom(32), os.urandom(32)
    controller = MembershipController.create_group(gid, [a, b])
    state = controller.state
    leaf_a = state.members[a].leaf_index
    leaf_b = state.members[b].leaf_index

    sender = GroupMessenger(state, sender_leaf_index=leaf_a)
    receiver = GroupMessenger(state, sender_leaf_index=leaf_b)
    msg = sender.encrypt(b"authenticated")
    tampered = GroupMessage(
        header=msg.header,
        ciphertext=msg.ciphertext[:-1] + bytes([msg.ciphertext[-1] ^ 0x01]),
    )

    with pytest.raises(InvalidTag):
        receiver.decrypt(tampered)
    assert receiver.decrypt(msg) == b"authenticated"


def test_group_replay_cache_eviction_allows_new_messages() -> None:
    """A full bounded replay cache evicts old entries instead of dropping all new messages."""
    gid = _rand_id()
    a, b = os.urandom(32), os.urandom(32)
    controller = MembershipController.create_group(gid, [a, b])
    state = controller.state
    leaf_a = state.members[a].leaf_index
    leaf_b = state.members[b].leaf_index

    sender = GroupMessenger(state, sender_leaf_index=leaf_a)
    receiver = GroupMessenger(state, sender_leaf_index=leaf_b, max_replay_entries=1)
    msg1 = sender.encrypt(b"one")
    msg2 = sender.encrypt(b"two")

    assert receiver.decrypt(msg1) == b"one"
    assert receiver.decrypt(msg2) == b"two"


def test_group_replay_cache_is_epoch_scoped() -> None:
    """Counter 0 in a new epoch is not a replay of counter 0 from an old key."""
    gid = _rand_id()
    a, b = os.urandom(32), os.urandom(32)
    controller = MembershipController.create_group(gid, [a, b])
    state = controller.state
    leaf_a = state.members[a].leaf_index
    leaf_b = state.members[b].leaf_index

    sender_epoch1 = GroupMessenger(state, sender_leaf_index=leaf_a)
    receiver = GroupMessenger(state, sender_leaf_index=leaf_b)
    assert receiver.decrypt(sender_epoch1.encrypt(b"epoch one")) == b"epoch one"

    controller.add_member(os.urandom(32))
    sender_epoch2 = GroupMessenger(state, sender_leaf_index=leaf_a)
    assert receiver.decrypt(sender_epoch2.encrypt(b"epoch two")) == b"epoch two"


def test_malformed_serialized_group_state_rejected() -> None:
    """Malformed or inconsistent group state update is rejected safely."""
    res = validate_serialized({})
    assert not res.success
    assert "missing" in res.errors[0].lower() or "epoch" in res.errors[0].lower()

    res = validate_serialized({"group_id": "x", "epoch": 0, "members": [], "group_secret": "x", "application_key": "x", "group_hash": "x", "node_secrets": [], "leaf_offset": 0})
    assert not res.success  # epoch must be >= 1


def test_group_hash_state_verification_detects_divergence() -> None:
    """Group hash / state verification detects divergence."""
    gid = _rand_id()
    a, b = os.urandom(32), os.urandom(32)
    ctrl = MembershipController.create_group(gid, [a, b])
    summary_a = summarize_state(ctrl.state)
    summary_b = summarize_state(ctrl.state)
    res = validate_incoming_state(summary_a, summary_b)
    assert res.success

    ctrl.add_member(os.urandom(32))
    summary_new = summarize_state(ctrl.state)
    res = validate_incoming_state(summary_a, summary_new)
    assert not res.success or summary_new.epoch != summary_a.epoch
