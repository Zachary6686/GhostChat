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
    # New ratchet keys reset message numbers.
    assert not detect_fork(state, b"rk2", 0, 2)


def test_no_fork_on_out_of_order_message_number() -> None:
    state = ForkDetectionState()
    assert not detect_fork(state, b"rk1", 5, 0)
    assert not detect_fork(state, b"rk1", 3, 0)


def test_no_fork_on_prev_chain_len_reset_for_new_key() -> None:
    state = ForkDetectionState()
    assert not detect_fork(state, b"rk1", 0, 5)
    assert not detect_fork(state, b"rk2", 0, 3)


def test_fork_on_same_ratchet_key_with_conflicting_prev_chain_len() -> None:
    state = ForkDetectionState()
    assert not detect_fork(state, b"rk1", 0, 5)
    assert detect_fork(state, b"rk1", 1, 3)

