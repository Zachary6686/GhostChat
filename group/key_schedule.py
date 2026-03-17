from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from crypto.hkdf import hkdf_derive


@dataclass
class TreeSecrets:
    """
    Container for the binary tree secrets used in the simplified MLS-style
    group key schedule.
    """

    node_secrets: List[Optional[bytes]]
    leaf_offset: int


def derive_leaf_node_secret(leaf_secret: bytes, leaf_index: int) -> bytes:
    return hkdf_derive(
        ikm=leaf_secret,
        salt=b"ghostchat-group-leaf",
        info=f"ghostchat-group-leaf:{leaf_index}".encode("ascii"),
        length=32,
    )


def derive_internal_node_secret(left: bytes, right: bytes, node_index: int) -> bytes:
    return hkdf_derive(
        ikm=left + right,
        salt=b"ghostchat-group-tree",
        info=f"ghostchat-group-node:{node_index}".encode("ascii"),
        length=32,
    )


def derive_epoch_secret(root_secret: bytes, epoch: int, group_id: bytes) -> bytes:
    return hkdf_derive(
        ikm=root_secret,
        salt=group_id,
        info=b"ghostchat-epoch-secret:" + epoch.to_bytes(8, "big"),
        length=32,
    )


def derive_application_key(epoch_secret: bytes) -> bytes:
    return hkdf_derive(
        ikm=epoch_secret,
        salt=b"ghostchat-app-key-salt",
        info=b"ghostchat-app-key",
        length=32,
    )


def derive_group_hash(
    *,
    group_id: bytes,
    epoch: int,
    member_ids: list[bytes],
    root_secret: bytes,
) -> bytes:
    payload = group_id + epoch.to_bytes(8, "big") + b"".join(sorted(member_ids))
    return hkdf_derive(
        ikm=payload + root_secret,
        salt=b"ghostchat-group-hash-salt",
        info=b"ghostchat-group-hash",
        length=32,
    )

