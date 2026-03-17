from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from network.timing_defense import (
    TimingDefenseConfig,
    apply_jitter,
    batch_messages,
    DelayStrategy,
    NoDelayStrategy,
    JitterDelayStrategy,
)


def test_deterministic_jitter_zero() -> None:
    cfg = TimingDefenseConfig(use_deterministic=True)
    t = 100.0
    assert apply_jitter(t, cfg) == t
    assert cfg.sample_jitter() == 0.0


def test_no_delay_strategy() -> None:
    s: DelayStrategy = NoDelayStrategy()
    assert s.delay_before_send({}) == 0.0


def test_jitter_delay_strategy_deterministic() -> None:
    cfg = TimingDefenseConfig(use_deterministic=True)
    s = JitterDelayStrategy(cfg)
    assert s.delay_before_send({}) == 0.0


def test_batch_messages_deterministic() -> None:
    cfg = TimingDefenseConfig(use_deterministic=True, max_batch_size=2)
    envelopes = [{"i": i} for i in range(5)]
    batched = batch_messages(envelopes, cfg, now=100.0)
    assert len(batched) == 5
    # All times should be 100.0 (no jitter)
    for ts, _ in batched:
        assert ts == 100.0


def test_timing_defense_does_not_change_envelope_content() -> None:
    """Batching/jitter only affect timing, not payload."""
    cfg = TimingDefenseConfig(use_deterministic=True, max_batch_size=1)
    env = {"recipient_locator": "bob", "sp": "abc"}
    batched = batch_messages([env], cfg, now=0.0)
    assert len(batched) == 1
    assert batched[0][1] is env
