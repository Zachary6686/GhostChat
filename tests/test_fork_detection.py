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
    # New ratchet chains reset their message numbers.
    assert not detect_fork(state, b"rk2", 0, 1)


def test_fork_on_message_number_regression() -> None:
    state = ForkDetectionState()
    assert not detect_fork(state, b"rk1", 5, 0)
    # Out-of-order delivery is handled by the ratchet and is not a fork.
    assert not detect_fork(state, b"rk1", 3, 0)


def test_fork_on_prev_chain_len_regression() -> None:
    state = ForkDetectionState()
    assert not detect_fork(state, b"rk1", 0, 5)
    # The previous-chain length is fixed for a ratchet key.
    assert detect_fork(state, b"rk1", 1, 3)


def test_fork_on_conflicting_previous_chain_length_for_same_key() -> None:
    state = ForkDetectionState()
    assert not detect_fork(state, b"rk1", 3, 7)
    assert detect_fork(state, b"rk1", 4, 8)

