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


def detect_fork(
    state: ForkDetectionState,
    ratchet_pub: bytes,
    msg_num: int,
    prev_chain_len: int,
) -> bool:
    """
    Return True if an impossible conflict is detected.

    Message numbers may arrive out of order within a ratchet chain. The
    invariant tracked here is that a given ratchet public key must announce
    a single previous-chain length.
    """

    previous = state.previous_chain_length_by_ratchet.get(ratchet_pub)
    if previous is not None and previous != prev_chain_len:
        return True
    state.previous_chain_length_by_ratchet[ratchet_pub] = prev_chain_len

    state.last_message_number = msg_num
    state.last_previous_chain_length = prev_chain_len
    state.last_ratchet_pub = ratchet_pub
    return False

