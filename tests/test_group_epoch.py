from __future__ import annotations

import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from group.membership import MembershipController
from group.state_verification import summarize_state, verify_consistency


def _gid() -> bytes:
    return os.urandom(16)


def test_group_epoch_rotation_and_consistency() -> None:
    gid = _gid()
    a = os.urandom(32)
    b = os.urandom(32)

    controller = MembershipController.create_group(gid, [a, b])
    state1 = controller.state
    summary1 = summarize_state(state1)

    c = os.urandom(32)
    controller.add_member(c)
    state2 = controller.state
    summary2 = summarize_state(state2)

    # Epoch must not decrease; the hash must change across membership
    # changes even if intermediate rotations are consolidated.
    assert state2.epoch >= state1.epoch
    assert summary2.group_hash != summary1.group_hash
    assert verify_consistency(state2, [summary2], previous_epoch=state1.epoch)

