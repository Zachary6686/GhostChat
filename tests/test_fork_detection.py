from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from protocol.fork_detection import ForkDetectionState, detect_fork


def test_no_fork_on_monotonic_progress() -> None:
    state = ForkDetectionState()
    assert not detect_fork(state, b"rk1", 0, 0)
    assert not detect_fork(state, b"rk1", 1, 0)
    # New ratchet key resets message numbering in a normal DH ratchet step.
    assert not detect_fork(state, b"rk2", 0, 1)


def test_no_fork_on_out_of_order_message_number() -> None:
    state = ForkDetectionState()
    assert not detect_fork(state, b"rk1", 5, 0)
    assert not detect_fork(state, b"rk1", 3, 0)


def test_fork_on_conflicting_prev_chain_len_for_same_ratchet_key() -> None:
    state = ForkDetectionState()
    assert not detect_fork(state, b"rk1", 0, 5)
    # The same ratchet key should not appear with a different PN value.
    assert detect_fork(state, b"rk1", 1, 3)


def test_no_fork_on_lower_prev_chain_len_for_new_ratchet_key() -> None:
    state = ForkDetectionState()
    assert not detect_fork(state, b"rk1", 0, 5)
    assert not detect_fork(state, b"rk2", 0, 1)

