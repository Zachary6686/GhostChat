from __future__ import annotations

"""
Network scheduling helpers.

This module is intended to orchestrate mix delays, timing jitter,
batching, cover traffic, and dummy packets at the relay level. The
current implementation is a placeholder that can be extended by the
server code.
"""

from dataclasses import dataclass
from typing import List

from .mix_router import MixRouter, ScheduledEnvelope
from .timing_defense import TimingDefenseConfig, batch_messages


@dataclass
class NetworkScheduler:
    mix_router: MixRouter
    timing_config: TimingDefenseConfig

    def schedule(self, envelopes: list[dict]) -> List[ScheduledEnvelope]:
        """
        Apply batching and mix delays to a batch of envelopes.
        """

        batched = batch_messages(envelopes, self.timing_config)
        scheduled: List[ScheduledEnvelope] = []
        for ts, env in batched:
            scheduled.append(self.mix_router.schedule_envelope(env, now=ts))
        return scheduled

