from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable, List, Tuple

from .group_state import GroupState


@dataclass
class MembershipController:
    """
    High-level helper for managing group membership operations.
    """

    state: GroupState

    @classmethod
    def create_group(cls, group_id: bytes, members: Iterable[bytes]) -> "MembershipController":
        """
        Create a new group with the given member identity public keys.

        Each member is assigned an independent random leaf secret.
        """

        initial: List[Tuple[bytes, bytes]] = []
        for identity_pk in members:
            leaf_secret = os.urandom(32)
            initial.append((identity_pk, leaf_secret))
        state = GroupState.create(group_id=group_id, initial_members=initial)
        return cls(state=state)

    def add_member(self, identity_pk: bytes) -> None:
        """
        Add a new member with a fresh random leaf secret and advance the epoch.
        """

        leaf_secret = os.urandom(32)
        self.state.add_member(identity_pk, leaf_secret)

    def remove_member(self, identity_pk: bytes) -> None:
        """
        Remove an existing member and advance the epoch.
        """

        replacement_secret = os.urandom(32)
        self.state.remove_member(identity_pk, replacement_secret)

