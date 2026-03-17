from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from network.mix_router import MixConfig, MixRouter, ScheduledEnvelope
from server.router import Router, get_routing_recipient


def test_mix_router_delay_range() -> None:
    cfg = MixConfig(min_delay=0.01, max_delay=0.05)
    router = MixRouter(cfg)
    now = 1000.0
    env = {"ciphertext": b"x"}

    scheduled = router.schedule_envelope(env, now=now)
    assert now + cfg.min_delay <= scheduled.deliver_at <= now + cfg.max_delay


def test_mix_router_disabled_no_delay() -> None:
    cfg = MixConfig(enabled=False, min_delay=1.0, max_delay=2.0)
    router = MixRouter(cfg)
    now = 1000.0
    scheduled = router.schedule_envelope({"x": 1}, now=now)
    assert scheduled.deliver_at == now


def test_mix_router_deterministic_mode() -> None:
    cfg = MixConfig(
        enabled=True,
        deterministic_mode=True,
        fixed_delay_sec=0.5,
    )
    router = MixRouter(cfg)
    now = 100.0
    s1 = router.schedule_envelope({"a": 1}, now=now)
    s2 = router.schedule_envelope({"b": 2}, now=now)
    assert s1.deliver_at == 100.5
    assert s2.deliver_at == 100.5


def test_router_delayed_delivery_delivers_successfully() -> None:
    """Delayed routing: envelope is delivered after deliver_due(now)."""
    from network.mix_router import MixConfig, MixRouter

    mix = MixRouter(MixConfig(deterministic_mode=True, fixed_delay_sec=0.0))
    router = Router(mix_router=mix)
    env = {"recipient_locator": "bob", "ttl": 60, "sp": "dGVzdA" + "Y" * 32, "v": 1, "pad": ""}

    router.enqueue_by_envelope(env, use_mix=True, now=1000.0)
    assert len(router.mailboxes) == 0
    n = router.deliver_due(now=1000.0)
    assert n == 1
    msgs = router.dequeue_all("bob")
    assert len(msgs) == 1
    assert msgs[0] == env

