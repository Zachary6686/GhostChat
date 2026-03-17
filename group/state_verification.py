from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List

from .group_state import GroupState
from .errors import GroupStateVerificationError, InvalidGroupStateError


@dataclass
class GroupStateSummary:
    group_id: bytes
    epoch: int
    group_hash: bytes
    member_ids: List[bytes]


@dataclass
class ValidationResult:
    """Structured result of group state or commit validation."""

    success: bool
    errors: List[str] = field(default_factory=list)

    def raise_if_invalid(self) -> None:
        if not self.success:
            raise GroupStateVerificationError("; ".join(self.errors))


def summarize_state(state: GroupState) -> GroupStateSummary:
    if state.group_hash is None:
        raise ValueError("GroupState missing group_hash")
    return GroupStateSummary(
        group_id=state.group_id,
        epoch=state.epoch,
        group_hash=state.group_hash,
        member_ids=sorted(state.members.keys()),
    )


def validate_local_state(state: GroupState) -> ValidationResult:
    """Validate a local group state. Returns structured result."""
    errors = state.validate()
    return ValidationResult(success=len(errors) == 0, errors=errors)


def validate_incoming_state(
    local_summary: GroupStateSummary,
    remote_summary: GroupStateSummary,
    previous_epoch: int | None = None,
) -> ValidationResult:
    """
    Validate an incoming state/commit against local view.
    Returns success if remote is consistent and epoch is monotonic.
    """
    errors: List[str] = []
    if remote_summary.group_id != local_summary.group_id:
        errors.append("group_id mismatch")
    if previous_epoch is not None and remote_summary.epoch < previous_epoch:
        errors.append("stale epoch")
    if remote_summary.epoch != local_summary.epoch and not errors:
        # Allow different epoch if we're applying an update
        pass
    if remote_summary.member_ids != local_summary.member_ids:
        errors.append("membership list mismatch")
    if remote_summary.group_hash != local_summary.group_hash and remote_summary.epoch == local_summary.epoch:
        errors.append("group_hash mismatch for same epoch")
    return ValidationResult(success=len(errors) == 0, errors=errors)


def validate_serialized(data: Dict[str, Any]) -> ValidationResult:
    """Validate that serialized group state has required fields and types."""
    errors: List[str] = []
    required = ["group_id", "epoch", "members", "group_secret", "application_key", "group_hash", "node_secrets", "leaf_offset"]
    for key in required:
        if key not in data:
            errors.append(f"missing field: {key}")
    if "epoch" in data:
        try:
            e = int(data["epoch"])
            if e < 1:
                errors.append("epoch must be >= 1")
        except (TypeError, ValueError):
            errors.append("invalid epoch")
    if "members" in data and not isinstance(data["members"], list):
        errors.append("members must be a list")
    return ValidationResult(success=len(errors) == 0, errors=errors)


def verify_consistency(
    local_state: GroupState,
    remote_summaries: Iterable[GroupStateSummary],
    previous_epoch: int | None = None,
) -> bool:
    """
    Verify that the local state is consistent with summaries reported by
    other members and with monotonic epoch progression.

    Checks:
    - epoch numbers match
    - group_id matches
    - group_hash matches membership and root (precomputed in state)
    - membership lists are identical
    - epoch >= previous_epoch (if provided)
    """

    local_summary = summarize_state(local_state)

    if previous_epoch is not None and local_summary.epoch < previous_epoch:
        return False

    for remote in remote_summaries:
        if remote.group_id != local_summary.group_id:
            return False
        if remote.epoch != local_summary.epoch:
            return False
        if remote.group_hash != local_summary.group_hash:
            return False
        if remote.member_ids != local_summary.member_ids:
            return False
    return True

