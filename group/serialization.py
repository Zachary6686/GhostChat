from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List

from crypto.serialization import b64u_decode, b64u_encode
from .group_state import GroupMember, GroupState, GroupTree


@dataclass
class SerializableGroupState:
    group_id: str
    epoch: int
    members: List[Dict[str, Any]]
    group_secret: str
    application_key: str
    group_hash: str
    node_secrets: List[str | None]
    leaf_offset: int


def serialize_group_state(state: GroupState) -> Dict[str, Any]:
    members_payload = []
    for identity_pk, member in state.members.items():
        members_payload.append(
            {
                "identity_pk": b64u_encode(identity_pk),
                "leaf_index": member.leaf_index,
            }
        )

    node_secrets = [
        b64u_encode(s) if s is not None else None for s in state.tree.node_secrets
    ]

    return asdict(
        SerializableGroupState(
            group_id=b64u_encode(state.group_id),
            epoch=state.epoch,
            members=members_payload,
            group_secret=b64u_encode(state.group_secret or b""),
            application_key=b64u_encode(state.application_key or b""),
            group_hash=b64u_encode(state.group_hash or b""),
            node_secrets=node_secrets,
            leaf_offset=state.tree.leaf_offset,
        )
    )


def deserialize_group_state(data: Dict[str, Any]) -> GroupState:
    from .state_verification import validate_serialized
    from .errors import InvalidGroupStateError

    result = validate_serialized(data)
    if not result.success:
        raise InvalidGroupStateError("; ".join(result.errors))
    group_id = b64u_decode(data["group_id"])
    epoch = int(data["epoch"])

    members_dict: Dict[bytes, GroupMember] = {}
    for m in data["members"]:
        identity_pk = b64u_decode(m["identity_pk"])
        members_dict[identity_pk] = GroupMember(
            identity_pk=identity_pk,
            leaf_index=int(m["leaf_index"]),
        )

    node_secrets_raw = data["node_secrets"]
    node_secrets = [
        b64u_decode(s) if isinstance(s, str) else None for s in node_secrets_raw
    ]
    leaf_offset = int(data["leaf_offset"])
    tree = GroupTree(node_secrets=node_secrets, leaf_offset=leaf_offset)

    group_secret = b64u_decode(data["group_secret"])
    application_key = b64u_decode(data["application_key"])
    group_hash = b64u_decode(data["group_hash"])

    return GroupState(
        group_id=group_id,
        epoch=epoch,
        tree=tree,
        members=members_dict,
        group_secret=group_secret,
        application_key=application_key,
        group_hash=group_hash,
    )

