from __future__ import annotations

"""
Replay protection utilities for protocol-level one-to-one messages.

This module provides a bounded replay cache keyed by session, ratchet
key, and message number. It is deterministic and testable.
"""

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, Tuple

from .envelope import ProtocolEnvelope


CacheKey = Tuple[bytes, bytes, int]  # (session_id, sender_ratchet_key, message_number)


@dataclass
class SessionReplayCache:
    max_entries: int = 1024
    seen: "OrderedDict[CacheKey, None]" = field(default_factory=OrderedDict)
    highest_by_ratchet: Dict[bytes, int] = field(default_factory=dict)

    def _make_key(self, env: ProtocolEnvelope) -> CacheKey:
        return (env.session_id, env.sender_ratchet_key, env.message_number)

    def accept(self, env: ProtocolEnvelope) -> bool:
        """
        Return True if this envelope is accepted as fresh; False if it
        should be treated as a replay.
        """

        if not self.check(env):
            return False
        self.record(env)
        return True

    def check(self, env: ProtocolEnvelope) -> bool:
        """
        Return True if this envelope has not already been accepted.

        Ordering is enforced by the double ratchet itself so out-of-order
        packets can still be decrypted with skipped keys.
        """

        key = self._make_key(env)
        return key not in self.seen

    def record(self, env: ProtocolEnvelope) -> None:
        """Record a successfully decrypted envelope in the bounded cache."""

        key = self._make_key(env)
        if key in self.seen:
            return
        while len(self.seen) >= self.max_entries:
            self.seen.popitem(last=False)
        self.seen[key] = None
        last = self.highest_by_ratchet.get(env.sender_ratchet_key)
        if last is None or env.message_number > last:
            self.highest_by_ratchet[env.sender_ratchet_key] = env.message_number

