from __future__ import annotations

import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from group.epoch_manager import EpochManager
from group.group_ratchet import GroupRatchet
from group.group_state import GroupState
from group.membership import MembershipController
from group.state_verification import summarize_state, verify_consistency


def _random_id() -> bytes:
    return os.urandom(16)


def test_group_creation_and_basic_messaging() -> None:
    group_id = _random_id()
    member_a = os.urandom(32)
    member_b = os.urandom(32)

    controller = MembershipController.create_group(group_id, [member_a, member_b])
    state_a = controller.state

    # For testing we give member B an identical copy of the state.
    state_b = GroupState(
        group_id=state_a.group_id,
        epoch=state_a.epoch,
        tree=state_a.tree,
        members=state_a.members.copy(),
        group_secret=state_a.group_secret,
    )

    ratchet_a = GroupRatchet(state_a)
    ratchet_b = GroupRatchet(state_b)

    msg = ratchet_a.encrypt(b"hello group")
    pt = ratchet_b.decrypt(msg)
    assert pt == b"hello group"


def test_member_join_cannot_decrypt_past_messages() -> None:
    group_id = _random_id()
    member_a = os.urandom(32)
    member_b = os.urandom(32)

    controller = MembershipController.create_group(group_id, [member_a, member_b])
    state_ab = controller.state
    ratchet_ab = GroupRatchet(state_ab)

    # Snapshot epoch-0 state for A/B.
    msg_before = ratchet_ab.encrypt(b"pre-join")

    # New member C joins.
    member_c = os.urandom(32)
    controller.add_member(member_c)
    state_abc = controller.state

    # C receives only new epoch-1 state.
    state_c = GroupState(
        group_id=state_abc.group_id,
        epoch=state_abc.epoch,
        tree=state_abc.tree,
        members=state_abc.members.copy(),
        group_secret=state_abc.group_secret,
    )
    ratchet_c = GroupRatchet(state_c)

    # C must not decrypt messages from prior epoch.
    try:
        _ = ratchet_c.decrypt(msg_before)
    except ValueError:
        pass
    else:  # pragma: no cover - defensive
        raise AssertionError("New member should not decrypt past messages")


def test_member_removal_cannot_decrypt_future_messages() -> None:
    group_id = _random_id()
    member_a = os.urandom(32)
    member_b = os.urandom(32)

    controller = MembershipController.create_group(group_id, [member_a, member_b])

    # Snapshot state for removed member B before removal.
    state_before = GroupState(
        group_id=controller.state.group_id,
        epoch=controller.state.epoch,
        tree=controller.state.tree,
        members=controller.state.members.copy(),
        group_secret=controller.state.group_secret,
    )
    ratchet_before = GroupRatchet(state_before)

    # Remove B.
    controller.remove_member(member_b)

    # Remaining members send a new message in the new epoch.
    state_after = controller.state
    ratchet_after = GroupRatchet(state_after)
    msg_after = ratchet_after.encrypt(b"post-removal")

    # Old state from B's perspective must not decrypt future messages.
    try:
        _ = ratchet_before.decrypt(msg_after)
    except ValueError:
        pass
    else:  # pragma: no cover - defensive
        raise AssertionError("Removed member should not decrypt future messages")


def test_group_state_verification_and_epoch_manager() -> None:
    group_id = _random_id()
    member_a = os.urandom(32)
    member_b = os.urandom(32)

    controller = MembershipController.create_group(group_id, [member_a, member_b])
    state1 = controller.state
    epoch_before = state1.epoch

    epoch_mgr = EpochManager()
    epoch_mgr.record(state1)

    # A and B both compute summaries and verify consistency.
    summary_a = summarize_state(state1)
    summary_b = summarize_state(state1)
    assert verify_consistency(state1, [summary_b])
    assert epoch_mgr.verify_state(state1)

    # After a membership change, hashes and epochs must change.
    controller.add_member(os.urandom(32))
    state2 = controller.state
    summary2 = summarize_state(state2)
    assert summary2.epoch == epoch_before + 1
    assert summary2.group_hash != summary_a.group_hash

