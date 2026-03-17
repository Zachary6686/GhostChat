from __future__ import annotations

import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterable, List, Tuple


@dataclass
class TimingDefenseConfig:
    """
    Configuration for simple timing jitter and batching defenses.

    use_deterministic: when True, jitter is zero (for tests).
    """

    min_jitter: float = 0.0
    max_jitter: float = 0.15
    max_batch_size: int = 8
    use_deterministic: bool = False

    def sample_jitter(self) -> float:
        if self.use_deterministic:
            return 0.0
        return random.uniform(self.min_jitter, self.max_jitter)


def apply_jitter(base_time: float, config: TimingDefenseConfig) -> float:
    """Apply a small random jitter to a base timestamp (zero if deterministic)."""
    return base_time + config.sample_jitter()


class DelayStrategy(ABC):
    """Abstract delay strategy for timing hardening; pluggable for tests."""

    @abstractmethod
    def delay_before_send(self, envelope: dict) -> float:
        """Return seconds to wait before sending this envelope (0 = no delay)."""
        ...


class NoDelayStrategy(DelayStrategy):
    """No delay; sends immediately."""

    def delay_before_send(self, envelope: dict) -> float:
        return 0.0


class JitterDelayStrategy(DelayStrategy):
    """Uses TimingDefenseConfig to sample jitter as send delay."""

    def __init__(self, config: TimingDefenseConfig) -> None:
        self.config = config

    def delay_before_send(self, envelope: dict) -> float:
        return self.config.sample_jitter()


def batch_messages(
    envelopes: Iterable[dict],
    config: TimingDefenseConfig,
    now: float | None = None,
) -> List[Tuple[float, dict]]:
    """
    Batch messages into small groups with randomized send times.
    Returns a list of (scheduled_time, envelope) tuples.
    """
    base = now if now is not None else time.time()
    batched: List[Tuple[float, dict]] = []
    batch: List[dict] = []

    for env in envelopes:
        batch.append(env)
        if len(batch) >= config.max_batch_size:
            send_time = apply_jitter(base, config)
            for e in batch:
                batched.append((send_time, e))
            batch = []
            base = send_time

    if batch:
        send_time = apply_jitter(base, config)
        for e in batch:
            batched.append((send_time, e))

    return batched

