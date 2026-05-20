from __future__ import annotations

"""
Group manager for client-side group state and messaging.

Holds one controller (or state-only holder) per group; provides create_group,
add_member, remove_member, and access to GroupMessenger for sending.
"""

from typing import Dict, List, Optional, Tuple

from group.group_state import GroupState
from group.group_messaging import GroupMessenger
from group.membership import MembershipController


class _StateOnlyHolder:
    """Holds group state for a member who joined (no add/remove capability)."""

    def __init__(self, state: GroupState) -> None:
        self.state = state

    def add_member(self, identity_pk: bytes) -> None:
        raise NotImplementedError("Only group creator can add members")

    def remove_member(self, identity_pk: bytes) -> None:
        raise NotImplementedError("Only group creator can remove members")


class GroupManager:
    """
    Manages group state and messengers for a single client (identity).
    Groups are keyed by group_id (bytes).
    """

    def __init__(self, identity_pk: bytes) -> None:
        self._identity_pk = identity_pk
        self._groups: Dict[bytes, Tuple[object, int]] = {}  # controller or _StateOnlyHolder, my_leaf_index
        self._senders: Dict[bytes, GroupMessenger] = {}  # cached sender, preserves per-epoch counters
        self._receivers: Dict[bytes, GroupMessenger] = {}  # cached receiver for decrypt (persists replay cache)

    def create_group(self, group_id: bytes, member_ids: List[bytes]) -> None:
        """
        Create a new group. identity_pk must be in member_ids; our leaf index
        is the index of identity_pk in member_ids.
        """
        if self._identity_pk not in member_ids:
            raise ValueError("identity_pk must be in member_ids")
        if group_id in self._groups:
            raise ValueError("Group already exists")
        controller = MembershipController.create_group(group_id, member_ids)
        my_leaf_index = member_ids.index(self._identity_pk)
        self._groups[group_id] = (controller, my_leaf_index)

    def add_group_member(self, group_id: bytes, member_id: bytes) -> None:
        """Add a member; epoch advances. Caller must distribute new state to members."""
        controller, idx = self._groups[group_id]
        controller.add_member(member_id)
        self._senders.pop(group_id, None)
        self._receivers.pop(group_id, None)

    def remove_group_member(self, group_id: bytes, member_id: bytes) -> None:
        """Remove a member; epoch advances."""
        controller, idx = self._groups[group_id]
        controller.remove_member(member_id)
        self._senders.pop(group_id, None)
        self._receivers.pop(group_id, None)

    def get_state(self, group_id: bytes) -> Optional[GroupState]:
        """Return current group state or None."""
        if group_id not in self._groups:
            return None
        return self._groups[group_id][0].state

    def get_messenger(self, group_id: bytes) -> Optional[GroupMessenger]:
        """Return a GroupMessenger for sending, or None."""
        if group_id not in self._groups:
            return None
        controller, my_leaf_index = self._groups[group_id]
        sender = self._senders.get(group_id)
        if sender is None or sender.state is not controller.state:
            sender = GroupMessenger(controller.state, sender_leaf_index=my_leaf_index)
            self._senders[group_id] = sender
        return sender

    def get_receiver(self, group_id: bytes) -> Optional[GroupMessenger]:
        """Return a GroupMessenger used only for decrypt (replay cache persisted)."""
        if group_id not in self._groups:
            return None
        if group_id not in self._receivers:
            self._receivers[group_id] = GroupMessenger(
                self._groups[group_id][0].state,
                sender_leaf_index=0,
            )
        return self._receivers[group_id]

    def join_group(self, group_id: bytes, state: GroupState, my_leaf_index: int) -> None:
        """
        Join an existing group with state received from another member.
        Used when we are added and receive the new epoch state.
        """
        if group_id in self._groups:
            raise ValueError("Already in group")
        self._groups[group_id] = (_StateOnlyHolder(state), my_leaf_index)
        self._senders.pop(group_id, None)
        self._receivers.pop(group_id, None)

    def set_state(self, group_id: bytes, controller: MembershipController, my_leaf_index: int) -> None:
        """Set or replace group state (e.g. after receiving updated state)."""
        self._groups[group_id] = (controller, my_leaf_index)
        self._senders.pop(group_id, None)
        self._receivers.pop(group_id, None)
