from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from protocol.envelope import ProtocolEnvelope, CURRENT_VERSION
from protocol.replay_protection import SessionReplayCache


def _env(session_id: bytes, rk: bytes, n: int) -> ProtocolEnvelope:
    return ProtocolEnvelope(
        version=CURRENT_VERSION,
        session_id=session_id,
        sender_ratchet_key=rk,
        message_number=n,
        previous_chain_length=0,
        ciphertext=b"c",
        nonce=b"",
        meta={},
    )


def test_replay_cache_rejects_exact_duplicates_only() -> None:
    cache = SessionReplayCache(max_entries=4)
    env1 = _env(b"s", b"rk", 1)
    env2 = _env(b"s", b"rk", 2)
    env3 = _env(b"s", b"rk", 1)

    assert cache.accept(env1)
    assert cache.accept(env2)
    assert not cache.accept(env3)

    # Lower unseen numbers can be legitimate out-of-order packets; the
    # double ratchet decides whether they are decryptable.
    assert cache.accept(_env(b"s", b"rk", 0))


def test_replay_cache_bounded_capacity() -> None:
    cache = SessionReplayCache(max_entries=2)
    assert cache.accept(_env(b"s", b"rk", 1))
    assert cache.accept(_env(b"s", b"rk", 2))
    # New, distinct envelopes evict the oldest entry instead of wedging the session.
    assert cache.accept(_env(b"s", b"rk", 3))
    assert cache.accept(_env(b"s", b"rk", 1))

