from __future__ import annotations

"""
TTL utilities for the relay server.
"""

import time


def is_expired(created_at: float, ttl: int, now: float | None = None) -> bool:
    now_ts = now if now is not None else time.time()
    return created_at + ttl < now_ts

