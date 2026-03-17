from __future__ import annotations

import os
import random
import time
from dataclasses import dataclass
from typing import Optional

from protocol.sealed_sender import make_dummy_sealed_outer


@dataclass
class CoverTrafficConfig:
    """
    Configuration for periodic cover traffic.

    Intervals are randomized within [min_interval, max_interval] seconds.
    deterministic_interval_sec is used when deterministic_mode is True (tests).
    """

    enabled: bool = True
    min_interval: float = 3.0
    max_interval: float = 10.0
    deterministic_mode: bool = False
    deterministic_interval_sec: float = 1.0
    recipient_locator: str = "cover"  # decoy recipient for routing

    def sample_interval(self) -> float:
        if self.deterministic_mode:
            return self.deterministic_interval_sec
        return random.uniform(self.min_interval, self.max_interval)


@dataclass
class CoverPacket:
    """
    Representation of a cover packet at the application level.

    On the wire, cover packets use the same sealed outer format as real
    traffic; this structure is only used locally.
    """

    envelope: dict
    scheduled_at: float


class CoverTrafficScheduler:
    """
    Generates periodic cover packets in sealed sender outer format.
    Client calls maybe_generate_cover_packet(now) to get a packet to send.
    """

    def __init__(self, config: CoverTrafficConfig | None = None) -> None:
        self.config = config or CoverTrafficConfig()
        self._next_time: Optional[float] = None

    def next_scheduled_time(self, now: float | None = None) -> Optional[float]:
        if not self.config.enabled:
            return None
        now_ts = now if now is not None else time.time()
        if self._next_time is None or self._next_time <= now_ts:
            self._next_time = now_ts + self.config.sample_interval()
        return self._next_time

    def maybe_generate_cover_packet(
        self,
        now: float | None = None,
        recipient_locator: Optional[str] = None,
    ) -> Optional[CoverPacket]:
        if not self.config.enabled:
            return None
        now_ts = now if now is not None else time.time()
        # Generate when we have reached or passed the scheduled fire time.
        if self._next_time is not None and now_ts < self._next_time:
            return None
        if self._next_time is None:
            self._next_time = now_ts

        locator = recipient_locator or self.config.recipient_locator
        payload_len = random.randint(64, 256) if not self.config.deterministic_mode else 64
        envelope = make_dummy_sealed_outer(
            recipient_locator=locator,
            ttl=0,
            payload_size=payload_len,
        )

        pkt = CoverPacket(envelope=envelope, scheduled_at=now_ts)
        self._next_time = now_ts + self.config.sample_interval()
        return pkt

