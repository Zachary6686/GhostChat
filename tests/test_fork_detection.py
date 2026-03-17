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
    # New ratchet key with higher message number should be fine.
    assert not detect_fork(state, b"rk2", 2, 1)


def test_fork_on_message_number_regression() -> None:
    state = ForkDetectionState()
    assert not detect_fork(state, b"rk1", 5, 0)
    assert detect_fork(state, b"rk1", 3, 0)


def test_fork_on_prev_chain_len_regression() -> None:
    state = ForkDetectionState()
    assert not detect_fork(state, b"rk1", 0, 5)
    # Previous chain length decreasing is suspicious.
    assert detect_fork(state, b"rk1", 1, 3)

