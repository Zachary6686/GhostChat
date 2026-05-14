from __future__ import annotations

"""
Fork detection helpers.

This module provides a placeholder interface for tracking impossible
state transitions (e.g., regressions in message numbers or conflicting
ratchet keys) and flagging sessions as suspicious. Detailed integration
with ratchet state is left to higher layers.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ForkDetectionState:
    """
    Minimal state for detecting obvious double-ratchet forks.
    """

    last_message_number: int = -1
    last_previous_chain_length: int = -1
    last_ratchet_pub: Optional[bytes] = None
    previous_chain_length_by_ratchet: dict[bytes, int] = field(default_factory=dict)


def detect_fork(
    state: ForkDetectionState,
    ratchet_pub: bytes,
    msg_num: int,
    prev_chain_len: int,
) -> bool:
    """
    Return True if an impossible regression or conflict is detected.

    Suspicious conditions:
      - the same ratchet public key is reused with a different
        previous_chain_length.

    Message numbers and previous-chain lengths are not globally monotonic in
    the double ratchet: message numbers reset on each DH ratchet and delayed
    packets may arrive from an older chain after a newer one.
    """

    known_prev_chain_len = state.previous_chain_length_by_ratchet.get(ratchet_pub)
    if known_prev_chain_len is not None and prev_chain_len != known_prev_chain_len:
        return True

    state.previous_chain_length_by_ratchet.setdefault(ratchet_pub, prev_chain_len)
    state.last_message_number = msg_num
    state.last_previous_chain_length = prev_chain_len
    state.last_ratchet_pub = ratchet_pub
    return False

