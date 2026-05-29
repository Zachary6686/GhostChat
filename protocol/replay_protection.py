from __future__ import annotations

"""
Replay protection utilities for protocol-level one-to-one messages.

This module provides a bounded replay cache keyed by session, ratchet
key, and message number. It is deterministic and testable.
"""

from dataclasses import dataclass, field
from typing import Dict, Set, Tuple

from .envelope import ProtocolEnvelope


CacheKey = Tuple[bytes, bytes, int]  # (session_id, sender_ratchet_key, message_number)


@dataclass
class SessionReplayCache:
    max_entries: int = 1024
    seen: Set[CacheKey] = field(default_factory=set)
    highest_by_ratchet: Dict[bytes, int] = field(default_factory=dict)

    def _make_key(self, env: ProtocolEnvelope) -> CacheKey:
        return (env.session_id, env.sender_ratchet_key, env.message_number)

    def check(self, env: ProtocolEnvelope) -> bool:
        """
        Return True if this envelope appears fresh without mutating state.
        """

        key = self._make_key(env)
        if key in self.seen:
            # Exact duplicate.
            return False

        last = self.highest_by_ratchet.get(env.sender_ratchet_key)
        if last is not None and env.message_number < last:
            # Stale message number for this ratchet key.
            return False

        # Bounded tracking: if at capacity and this is new, reject to
        # avoid unbounded memory growth.
        if len(self.seen) >= self.max_entries:
            return False

        return True

    def mark(self, env: ProtocolEnvelope) -> bool:
        """
        Mark an authenticated envelope as accepted.
        """
        if not self.check(env):
            return False
        key = self._make_key(env)
        last = self.highest_by_ratchet.get(env.sender_ratchet_key)
        self.seen.add(key)
        if last is None or env.message_number > last:
            self.highest_by_ratchet[env.sender_ratchet_key] = env.message_number
        return True

    def accept(self, env: ProtocolEnvelope) -> bool:
        """
        Return True if this envelope is accepted as fresh; False if it
        should be treated as a replay or stale.
        """
        return self.mark(env)

