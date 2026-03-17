from __future__ import annotations

"""
Storage models (skeleton).

This module would typically define ORM-like models or DTOs for identities,
sessions, groups, and messages.
"""

from dataclasses import dataclass


@dataclass
class IdentityRecord:
    identity_pk: bytes


@dataclass
class SessionRecord:
    peer_id: bytes

