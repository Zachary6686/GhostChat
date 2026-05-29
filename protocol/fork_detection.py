from __future__ import annotations

"""
Fork detection helpers.

This module provides a placeholder interface for tracking impossible
state transitions (e.g., regressions in message numbers or conflicting
ratchet keys) and flagging sessions as suspicious. Detailed integration
with ratchet state is left to higher layers.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ForkDetectionState:
    """
    Minimal state for detecting obvious double-ratchet forks.
    """

    last_message_number: int = -1
    last_previous_chain_length: int = -1
    last_ratchet_pub: Optional[bytes] = None


def detect_fork(
    state: ForkDetectionState,
    ratchet_pub: bytes,
    msg_num: int,
    prev_chain_len: int,
    *,
    commit: bool = True,
) -> bool:
    """
    Return True if an impossible regression or conflict is detected.

    Suspicious conditions:
      - message number regresses under the same ratchet key.
      - previous_chain_length regresses under the same ratchet key.

    Message numbers are scoped to a ratchet key, so a new ratchet key may
    legitimately reset the message number to zero.
    """

    # Regression of message number under same ratchet key.
    if state.last_ratchet_pub is not None and ratchet_pub == state.last_ratchet_pub:
        if msg_num < state.last_message_number:
            return True

    # Previous-chain-length going backwards under the same key is suspicious.
    if (
        state.last_ratchet_pub is not None
        and ratchet_pub == state.last_ratchet_pub
        and prev_chain_len < state.last_previous_chain_length
    ):
        return True

    if commit:
        state.last_message_number = msg_num
        state.last_previous_chain_length = prev_chain_len
        state.last_ratchet_pub = ratchet_pub
    return False

