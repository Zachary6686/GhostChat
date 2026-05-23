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
    previous_chain_lengths: Dict[bytes, int] = field(default_factory=dict)


def check_fork(
    state: ForkDetectionState,
    ratchet_pub: bytes,
    msg_num: int,
    prev_chain_len: int,
) -> bool:
    """
    Return True if the observed header contradicts prior authenticated headers.

    Message numbers legitimately arrive out of order and reset to zero on a new
    DH ratchet key, so only invariants scoped to one ratchet key are safe here.
    """

    previous_chain_len = state.previous_chain_lengths.get(ratchet_pub)
    if previous_chain_len is not None and prev_chain_len != previous_chain_len:
        return True
    return False


def commit_fork_observation(
    state: ForkDetectionState,
    ratchet_pub: bytes,
    msg_num: int,
    prev_chain_len: int,
) -> None:
    """
    Record an authenticated header after the ratchet decrypt succeeds.
    """

    state.previous_chain_lengths.setdefault(ratchet_pub, prev_chain_len)
    state.last_message_number = msg_num
    state.last_previous_chain_length = prev_chain_len
    state.last_ratchet_pub = ratchet_pub


def detect_fork(
    state: ForkDetectionState,
    ratchet_pub: bytes,
    msg_num: int,
    prev_chain_len: int,
) -> bool:
    """
    Return True if an impossible regression or conflict is detected.

    This compatibility helper both checks and records the observation. New
    receive paths should call check_fork() before decrypting and
    commit_fork_observation() only after successful authentication.
    """

    if check_fork(state, ratchet_pub, msg_num, prev_chain_len):
        return True
    commit_fork_observation(state, ratchet_pub, msg_num, prev_chain_len)
    return False

