from __future__ import annotations

"""
Replay protection utilities for protocol-level one-to-one messages.

This module provides a bounded replay cache keyed by session, ratchet
key, and message number. It is deterministic and testable.
"""

from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Set, Tuple

from .envelope import ProtocolEnvelope


CacheKey = Tuple[bytes, bytes, int]  # (session_id, sender_ratchet_key, message_number)


@dataclass
class SessionReplayCache:
    max_entries: int = 1024
    seen: Set[CacheKey] = field(default_factory=set)
    order: Deque[CacheKey] = field(default_factory=deque)

    def _make_key(self, env: ProtocolEnvelope) -> CacheKey:
        return (env.session_id, env.sender_ratchet_key, env.message_number)

    def is_replay(self, env: ProtocolEnvelope) -> bool:
        """
        Return True if this envelope's authenticated header was already seen.
        """

        return self._make_key(env) in self.seen

    def record(self, env: ProtocolEnvelope) -> bool:
        """
        Record an authenticated envelope as seen.

        The double ratchet supports out-of-order delivery, so lower message
        numbers on a ratchet key are not stale by themselves. Keep only exact
        header identities here and evict oldest entries to stay bounded.
        """

        key = self._make_key(env)
        if key in self.seen:
            return False

        if self.max_entries <= 0:
            return True

        while len(self.seen) >= self.max_entries and self.order:
            oldest = self.order.popleft()
            self.seen.discard(oldest)

        self.seen.add(key)
        self.order.append(key)
        return True

    def accept(self, env: ProtocolEnvelope) -> bool:
        """
        Return True if this envelope is accepted as fresh and record it.

        Session decryption code should prefer is_replay() before AEAD
        authentication and record() only after authentication succeeds.
        """

        if self.is_replay(env):
            return False
        return self.record(env)

