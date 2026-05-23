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

    def is_fresh(self, env: ProtocolEnvelope) -> bool:
        """
        Return True if this envelope has not already been accepted.
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

    def mark_accepted(self, env: ProtocolEnvelope) -> bool:
        """
        Commit a successfully authenticated envelope to the replay cache.
        """

        if not self.is_fresh(env):
            return False
        self.seen.add(self._make_key(env))
        return True

    def accept(self, env: ProtocolEnvelope) -> bool:
        """
        Backward-compatible check-and-mark helper.
        """

        return self.mark_accepted(env)

