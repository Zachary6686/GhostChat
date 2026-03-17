from __future__ import annotations

import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from group.membership import MembershipController


def _gid() -> bytes:
    return os.urandom(16)


def test_group_membership_add_and_remove() -> None:
    gid = _gid()
    a = os.urandom(32)
    b = os.urandom(32)

    controller = MembershipController.create_group(gid, [a, b])
    assert a in controller.state.members
    assert b in controller.state.members

    c = os.urandom(32)
    controller.add_member(c)
    assert c in controller.state.members

    controller.remove_member(b)
    assert b not in controller.state.members

