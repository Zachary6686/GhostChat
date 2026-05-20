from __future__ import annotations

"""
Replay protection utilities for protocol-level one-to-one messages.

This module provides a bounded replay cache keyed by session, ratchet
key, and message number. It is deterministic and testable.
"""

from dataclasses import dataclass, field
from typing import Set, Tuple

from .envelope import ProtocolEnvelope


CacheKey = Tuple[bytes, bytes, int]  # (session_id, sender_ratchet_key, message_number)


@dataclass
class SessionReplayCache:
    max_entries: int = 1024
    seen: Set[CacheKey] = field(default_factory=set)

    def _make_key(self, env: ProtocolEnvelope) -> CacheKey:
        return (env.session_id, env.sender_ratchet_key, env.message_number)

    def accept(self, env: ProtocolEnvelope) -> bool:
        """
        Return True if this envelope is accepted as fresh; False if it
        should be treated as a replay or stale.
        """
        return self.mark_seen(env)

    def can_accept(self, env: ProtocolEnvelope) -> bool:
        """
        Return True if this envelope can be marked after authentication.

        Message numbers are not required to be monotonic here: the double
        ratchet supports out-of-order delivery via skipped message keys.
        """
        key = self._make_key(env)
        if key in self.seen:
            # Exact duplicate.
            return False

        # Bounded tracking: if at capacity and this is new, reject to
        # avoid unbounded memory growth.
        if len(self.seen) >= self.max_entries:
            return False

        return True

    def mark_seen(self, env: ProtocolEnvelope) -> bool:
        """
        Mark an authenticated envelope as seen.
        """
        if not self.can_accept(env):
            return False
        key = self._make_key(env)
        self.seen.add(key)
        return True

