from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from crypto.hkdf import hkdf_derive
from .key_schedule import (
    derive_application_key,
    derive_epoch_secret,
    derive_group_hash,
    derive_internal_node_secret,
    derive_leaf_node_secret,
)


@dataclass
class GroupMember:
    identity_pk: bytes  # Ed25519 public key bytes
    leaf_index: int


@dataclass
class GroupTree:
    """
    Simple full binary tree of secrets stored as an array.

    Node indexing:
        0 = root
        left(i) = 2*i + 1
        right(i) = 2*i + 2

    Leaves occupy the last level that covers current members.
    """

    node_secrets: List[Optional[bytes]]
    leaf_offset: int

    @classmethod
    def for_member_count(cls, member_count: int) -> "GroupTree":
        """
        Create a tree sized for up to 4 members (prototype limit).

        This keeps the structure simple while still providing a
        tree-based schedule for small research groups.
        """

        if member_count <= 0:
            raise ValueError("member_count must be positive")
        if member_count > 4:
            raise ValueError("Prototype group size limit is 4 members")

        leaves = 4  # fixed capacity for this prototype
        total_nodes = 2 * leaves - 1
        leaf_offset = leaves - 1
        secrets: List[Optional[bytes]] = [None] * total_nodes
        return cls(node_secrets=secrets, leaf_offset=leaf_offset)

    def leaf_node_index(self, leaf_index: int) -> int:
        return self.leaf_offset + leaf_index

    def parent_index(self, idx: int) -> Optional[int]:
        if idx == 0:
            return None
        return (idx - 1) // 2

    def set_leaf(self, leaf_index: int, secret: bytes) -> None:
        node_idx = self.leaf_node_index(leaf_index)
        self.node_secrets[node_idx] = derive_leaf_node_secret(secret, leaf_index)
        self._recompute_path(node_idx)

    def _recompute_path(self, idx: int) -> None:
        # Walk up to root recomputing parent secrets from children.
        parent = self.parent_index(idx)
        while parent is not None:
            left = self.node_secrets[2 * parent + 1]
            right = self.node_secrets[2 * parent + 2]
            if left is None or right is None:
                # Tree might be partially populated; stop here.
                break
            self.node_secrets[parent] = derive_internal_node_secret(left, right, parent)
            parent = self.parent_index(parent)

    @property
    def root_secret(self) -> Optional[bytes]:
        return self.node_secrets[0]


INITIAL_EPOCH = 1


@dataclass
class GroupState:
    """
    MLS-inspired group state for a small GhostChat group.

    Canonical state: group_id, epoch, members (with leaf indexes), group_secret
    (epoch_secret), application_key, group_hash. Message counters are per-sender
    in GroupMessenger.
    """

    group_id: bytes
    epoch: int
    tree: GroupTree
    members: Dict[bytes, GroupMember] = field(default_factory=dict)  # keyed by identity_pk
    group_secret: bytes | None = None
    application_key: bytes | None = None
    group_hash: bytes | None = None

    @classmethod
    def create(cls, group_id: bytes, initial_members: List[Tuple[bytes, bytes]]) -> "GroupState":
        """
        Create a group with given members. Epoch starts at INITIAL_EPOCH (1).

        initial_members: list of (identity_pk, leaf_secret) tuples.
        """
        if not group_id:
            raise ValueError("group_id must be non-empty")
        if not initial_members:
            raise ValueError("initial_members must be non-empty")

        member_count = len(initial_members)
        tree = GroupTree.for_member_count(member_count)
        members: Dict[bytes, GroupMember] = {}
        for idx, (identity_pk, leaf_secret) in enumerate(initial_members):
            if identity_pk in members:
                raise ValueError("Duplicate member in initial_members")
            members[identity_pk] = GroupMember(identity_pk=identity_pk, leaf_index=idx)
            tree.set_leaf(idx, leaf_secret)

        total_leaves = (len(tree.node_secrets) + 1) // 2
        for pad_idx in range(member_count, total_leaves):
            filler = hkdf_derive(
                ikm=group_id,
                salt=b"ghostchat-group-padding",
                info=f"padding-{pad_idx}".encode("ascii"),
                length=32,
            )
            tree.set_leaf(pad_idx, filler)

        if tree.root_secret is None:
            raise ValueError("Tree root_secret not initialized")

        epoch = INITIAL_EPOCH
        epoch_secret = derive_epoch_secret(tree.root_secret, epoch=epoch, group_id=group_id)
        group_secret = epoch_secret
        application_key = derive_application_key(epoch_secret)
        group_hash = derive_group_hash(
            group_id=group_id,
            epoch=epoch,
            member_ids=list(members.keys()),
            root_secret=tree.root_secret,
        )
        return cls(
            group_id=group_id,
            epoch=epoch,
            tree=tree,
            members=members,
            group_secret=group_secret,
            application_key=application_key,
            group_hash=group_hash,
        )

    def _rederive_group_secret(self) -> None:
        root = self.tree.root_secret
        if root is None:
            raise ValueError("Tree root_secret not initialized")
        epoch_secret = derive_epoch_secret(root, self.epoch, self.group_id)
        self.group_secret = epoch_secret
        self.application_key = derive_application_key(epoch_secret)
        self.group_hash = derive_group_hash(
            group_id=self.group_id,
            epoch=self.epoch,
            member_ids=list(self.members.keys()),
            root_secret=root,
        )

    def add_member(self, identity_pk: bytes, leaf_secret: bytes) -> None:
        """
        Add a new member with a fresh leaf secret and advance epoch.

        New members must not learn previous epoch keys; they only receive
        the new epoch state derived from the updated tree.
        """

        if identity_pk in self.members:
            raise ValueError("Member already in group")

        # Allocate a new leaf index.
        new_index = len(self.members)
        self.members[identity_pk] = GroupMember(identity_pk=identity_pk, leaf_index=new_index)

        # If we exceed the current tree capacity, rebuild a larger tree and
        # repopulate existing leaves with fresh leaf secrets unknown to
        # removed members (if any). For simplicity we reuse the current
        # root_secret as source entropy for existing leaves.
        current_leaves = (len(self.tree.node_secrets) + 1) // 2
        if new_index >= current_leaves:
            # Rebuild tree with larger capacity.
            # Note: use the pre-join member set (size = new_index) so that
            # we only re-embed secrets for existing members; the new member
            # leaf is set below after the rebuild.
            old_members = [m for m in self.members.values() if m.leaf_index < new_index]
            new_tree = GroupTree.for_member_count(len(old_members) + 1)
            for m in old_members:
                # For existing members, derive a new leaf from prior group_secret
                # so that adding a member rotates secrets.
                leaf = hkdf_derive(
                    ikm=self.group_secret or b"\x00" * 32,
                    salt=b"ghostchat-group-rekey",
                    info=f"member-{m.leaf_index}".encode("ascii"),
                    length=32,
                )
                new_tree.set_leaf(m.leaf_index, leaf)
            self.tree = new_tree

        # Set leaf for the new member in current/possibly rebuilt tree.
        member = self.members[identity_pk]
        self.tree.set_leaf(member.leaf_index, leaf_secret)

        # Advance epoch and derive new group secret.
        self.epoch += 1
        self._rederive_group_secret()

    def remove_member(self, identity_pk: bytes, replacement_secret: bytes) -> None:
        """
        Remove an existing member and advance epoch.

        The removed member's leaf is overwritten with a fresh secret that
        is not shared with them, forcing a rekey so they cannot derive
        future group secrets.
        """

        member = self.members.pop(identity_pk, None)
        if member is None:
            raise ValueError("Member not in group")

        # Overwrite the removed member's leaf with replacement_secret.
        self.tree.set_leaf(member.leaf_index, replacement_secret)

        # Advance epoch and derive new group secret.
        self.epoch += 1
        self._rederive_group_secret()

    def compute_group_hash(self) -> bytes:
        """
        Compute a commitment to the current group configuration.

        Intended to be compared between honest members to detect
        divergence; it is not secret by itself.
        """
        member_ids = sorted(self.members.keys())
        payload = self.group_id + self.epoch.to_bytes(8, "big") + b"".join(member_ids)
        root = self.tree.root_secret or b""
        return hkdf_derive(
            ikm=payload + root,
            salt=b"ghostchat-group-hash-salt",
            info=b"ghostchat-group-hash",
            length=32,
        )

    def validate(self) -> list[str]:
        """
        Validate local group state. Returns a list of error strings; empty if valid.
        """
        errors: list[str] = []
        if not self.group_id:
            errors.append("group_id is empty")
        if self.epoch < INITIAL_EPOCH:
            errors.append("epoch is below initial")
        if not self.members:
            errors.append("no members")
        if self.tree.root_secret is None:
            errors.append("tree root_secret not set")
        if self.application_key is None:
            errors.append("application_key not set")
        if self.group_hash is None:
            errors.append("group_hash not set")
        elif self.group_hash != self.compute_group_hash():
            errors.append("group_hash does not match computed")
        seen_indexes: set[int] = set()
        for m in self.members.values():
            if m.leaf_index in seen_indexes:
                errors.append(f"duplicate leaf_index {m.leaf_index}")
            seen_indexes.add(m.leaf_index)
        return errors

