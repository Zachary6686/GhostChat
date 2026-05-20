from __future__ import annotations

"""
Fork detection helpers.

This module provides a placeholder interface for tracking impossible
state transitions (e.g., regressions in message numbers or conflicting
ratchet keys) and flagging sessions as suspicious. Detailed integration
with ratchet state is left to higher layers.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class ForkDetectionState:
    """
    Minimal state for detecting obvious double-ratchet forks.
    """

    last_message_number: int = -1
    last_previous_chain_length: int = -1
    last_ratchet_pub: Optional[bytes] = None
    previous_chain_length_by_ratchet: Dict[bytes, int] = field(default_factory=dict)

    def copy(self) -> "ForkDetectionState":
        return ForkDetectionState(
            last_message_number=self.last_message_number,
            last_previous_chain_length=self.last_previous_chain_length,
            last_ratchet_pub=self.last_ratchet_pub,
            previous_chain_length_by_ratchet=dict(self.previous_chain_length_by_ratchet),
        )


def detect_fork(
    state: ForkDetectionState,
    ratchet_pub: bytes,
    msg_num: int,
    prev_chain_len: int,
) -> bool:
    """
    Return True if an impossible regression or conflict is detected.

    Suspicious conditions:
      - the same ratchet key appears with conflicting previous-chain length.

    Message numbers and previous-chain lengths are not globally monotonic in a
    double ratchet: out-of-order messages may arrive with lower message numbers,
    and a new sending chain starts back at message number zero.
    """

    known_prev_chain_len = state.previous_chain_length_by_ratchet.get(ratchet_pub)
    if known_prev_chain_len is not None and prev_chain_len != known_prev_chain_len:
        return True

    state.previous_chain_length_by_ratchet[ratchet_pub] = prev_chain_len
    state.last_message_number = msg_num
    state.last_previous_chain_length = prev_chain_len
    state.last_ratchet_pub = ratchet_pub
    return False

