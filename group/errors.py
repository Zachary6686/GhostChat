from __future__ import annotations


class GroupError(Exception):
    """Base class for group-related errors in GhostChat."""


class EpochMismatchError(GroupError):
    """Raised when a group message refers to an unexpected or stale epoch."""


class MembershipError(GroupError):
    """Raised when membership or leaf-index checks fail."""


class GroupStateVerificationError(GroupError):
    """Raised when group state consistency verification fails."""


class ReplayedGroupMessageError(GroupError):
    """Raised when a duplicate group message (same sender, epoch, counter) is received."""


class InvalidGroupStateError(GroupError):
    """Raised when serialized or incoming group state is malformed or inconsistent."""

