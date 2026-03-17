from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from network.cover_traffic import CoverTrafficConfig, CoverTrafficScheduler
from network.dummy_packets import DummyPacket, make_dummy_envelope_like
from protocol.sealed_sender import is_sealed_envelope
from server.router import get_routing_recipient


def test_cover_traffic_packet_shape() -> None:
    cfg = CoverTrafficConfig(enabled=True, min_interval=0.0, max_interval=0.0)
    sched = CoverTrafficScheduler(cfg)
    pkt = sched.maybe_generate_cover_packet(now=100.0)
    assert pkt is not None
    assert "sp" in pkt.envelope
    assert "recipient_locator" in pkt.envelope
    assert is_sealed_envelope(pkt.envelope)


def test_cover_traffic_no_plaintext_required() -> None:
    """Cover packets can be generated without any application plaintext."""
    cfg = CoverTrafficConfig(
        enabled=True,
        deterministic_mode=True,
        deterministic_interval_sec=0.0,
    )
    sched = CoverTrafficScheduler(cfg)
    pkt = sched.maybe_generate_cover_packet(now=100.0)
    assert pkt is not None
    assert get_routing_recipient(pkt.envelope) == "cover"


def test_dummy_packet_cipher_randomized() -> None:
    real = {"ciphertext": b"a" * 16, "recipient": "user1", "ttl": 60}
    dummy = make_dummy_envelope_like(real)
    assert isinstance(dummy, DummyPacket)
    assert dummy.envelope["ciphertext"] != real["ciphertext"]
    assert dummy.envelope["ttl"] == 0


def test_cover_traffic_deterministic_interval() -> None:
    cfg = CoverTrafficConfig(
        enabled=True,
        deterministic_mode=True,
        deterministic_interval_sec=2.0,
    )
    sched = CoverTrafficScheduler(cfg)
    t1 = sched.next_scheduled_time(now=0.0)
    assert t1 == 2.0
    pkt = sched.maybe_generate_cover_packet(now=2.0)
    assert pkt is not None
    assert pkt.scheduled_at == 2.0

