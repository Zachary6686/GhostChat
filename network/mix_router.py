from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Iterable, List, Tuple


@dataclass
class MixConfig:
    """
    Configuration for mix-style random relay delays.

    Delays can be in seconds (min_delay/max_delay) or milliseconds
    (min_delay_ms/max_delay_ms). When deterministic_mode is True,
    fixed_delay_sec is used for tests.
    """

    enabled: bool = True
    min_delay: float = 0.05
    max_delay: float = 0.3
    min_delay_ms: int | None = None
    max_delay_ms: int | None = None
    deterministic_mode: bool = False
    fixed_delay_sec: float = 0.0

    def sample_delay(self) -> float:
        if not self.enabled:
            return 0.0
        if self.deterministic_mode:
            return self.fixed_delay_sec
        if self.min_delay_ms is not None and self.max_delay_ms is not None:
            ms = random.randint(self.min_delay_ms, self.max_delay_ms)
            return ms / 1000.0
        return random.uniform(self.min_delay, self.max_delay)


@dataclass
class ScheduledEnvelope:
    deliver_at: float
    envelope: dict


class MixRouter:
    """
    Stateless helper to assign randomized delivery times to envelopes.

    Intended usage in the relay server:
      - On receipt of an incoming envelope, call `schedule_envelope`.
      - Store the returned `ScheduledEnvelope` in an in-memory queue.
      - A background worker pops due items and forwards them.
    """

    def __init__(self, config: MixConfig | None = None) -> None:
        self.config = config or MixConfig()

    def schedule_envelope(self, envelope: dict, now: float | None = None) -> ScheduledEnvelope:
        base = now if now is not None else time.time()
        delay = self.config.sample_delay()
        return ScheduledEnvelope(deliver_at=base + delay, envelope=envelope)

    def schedule_batch(
        self, envelopes: Iterable[dict], now: float | None = None
    ) -> List[ScheduledEnvelope]:
        base = now if now is not None else time.time()
        scheduled: List[ScheduledEnvelope] = []
        for env in envelopes:
            delay = self.config.sample_delay()
            scheduled.append(ScheduledEnvelope(deliver_at=base + delay, envelope=env))
        return scheduled

