from __future__ import annotations

"""
In-memory mailbox store for the relay server.

Messages are held only in memory and expire via TTL; there is no
on-disk persistence.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple
import time


@dataclass
class StoredEnvelope:
    expires_at: float
    envelope: dict


@dataclass
class MemoryMailboxStore:
    mailboxes: Dict[str, List[StoredEnvelope]] = field(default_factory=dict)

    def put(self, recipient: str, envelope: dict, ttl: int) -> None:
        now = time.time()
        expires_at = now + ttl
        self.mailboxes.setdefault(recipient, []).append(StoredEnvelope(expires_at, envelope))

    def get_all(self, recipient: str) -> List[dict]:
        now = time.time()
        items = self.mailboxes.get(recipient, [])
        alive: List[StoredEnvelope] = []
        out: List[dict] = []
        for item in items:
            if item.expires_at >= now:
                out.append(item.envelope)
                alive.append(item)
        self.mailboxes[recipient] = alive
        return out

