from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

from .group_state import GroupState


@dataclass
class EpochRecord:
    epoch: int
    group_hash: bytes


@dataclass
class EpochManager:
    """
    Tracks group epochs and associated hashes for consistency checks.
    """

    history: Dict[int, EpochRecord] = field(default_factory=dict)

    def record(self, state: GroupState) -> None:
        h = state.compute_group_hash()
        self.history[state.epoch] = EpochRecord(epoch=state.epoch, group_hash=h)

    def latest(self) -> Optional[EpochRecord]:
        if not self.history:
            return None
        max_epoch = max(self.history.keys())
        return self.history[max_epoch]

    def verify_state(self, state: GroupState) -> bool:
        """
        Verify that the provided state matches our recorded hash for its epoch.
        """

        rec = self.history.get(state.epoch)
        if rec is None:
            return False
        return rec.group_hash == state.compute_group_hash()

