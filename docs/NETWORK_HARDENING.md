Network Hardening (Metadata-Focused)
====================================

This document describes the optional network hardening layer for GhostChat. The goal is to **reduce metadata leakage** and make simple traffic analysis more difficult, not to provide strong anonymity guarantees.

Components
----------

The `network/` package provides: `mix_router.py` (optional delayed delivery), `cover_traffic.py` (client cover packets in sealed format), `dummy_packets.py` (dummies in same outer shape as real traffic), `timing_defense.py` (jitter, batching, DelayStrategy), `scheduler.py`, and `config.py` (including `deterministic_network_config()` for tests).

Mix-Style Delayed Routing
-------------------------

- **MixConfig**: `enabled`, `min_delay`/`max_delay` or `min_delay_ms`/`max_delay_ms`; `deterministic_mode` and `fixed_delay_sec` for tests.
- **Router**: `enqueue_by_envelope(envelope, use_mix=True, now=...)` schedules; `deliver_due(now)` moves due envelopes into mailboxes. RAM-only; routing by `recipient_locator` only.

Effect:

- Breaks strict timing correlation between sender and receiver events.
- Introduces modest, configurable latency to make simple timing-based linkage harder.

Limitations:

- Does **not** provide strong anonymity.
- An adversary with global view and fine-grained timing can still correlate flows.

Cover Traffic
-------------

- **CoverTrafficScheduler**: cover packets use **sealed outer format** (same as real traffic). `maybe_generate_cover_packet(now)` returns a `CoverPacket`; no application plaintext required.
- **Client hook**: `message_api.get_pending_cover_packets(scheduler, now)` returns envelope dicts to send. Configurable and disableable for tests (`deterministic_mode`, `deterministic_interval_sec`).

Effect:

- Adds background noise so that real message bursts are less obvious.

Limitations:

- Cover traffic volume is modest and configurable; it does not saturate the channel.
- An observer can still identify high-activity periods, just with reduced clarity.

Dummy Packets
-------------

Dummies use the same sealed sender outer shape as real traffic. `make_dummy_sealed_outer` (protocol) and `make_dummy_sealed_envelope` (network) build envelope dicts with random `sp`. Relay routes by `recipient_locator`; recipient drops undecryptable envelopes (`recv_sealed(drop_undecryptable=True)`). `make_dummy_envelope_like(real_envelope)` remains for legacy-shaped envelopes.

Effect:

- Increases the number of packets that look like legitimate traffic.
- Makes it harder to distinguish “real” from “noise” purely by structure.

Limitations:

- If the deployment tags dummy packets in logs or telemetry, that metadata can leak.
- The indistinguishability only holds at the ciphertext/metadata level, not against deep endpoint inspection.

Timing-Defense Integration
--------------------------

- **TimingDefenseConfig**: `use_deterministic=True` gives zero jitter for tests.
- **DelayStrategy** (pluggable): `NoDelayStrategy`, `JitterDelayStrategy(config)`. Does not change envelope content or replay/fork semantics.
- `apply_jitter`, `batch_messages` for send-time jitter and batching.

Effect:

- Smooths out very fine-grained timing patterns.
- Reduces the ability of an attacker to match one-to-one message send/receive times.

Limitations:

- Jitter ranges are small to keep latency acceptable.
- Batching thresholds are low for usability, limiting the defense against sophisticated traffic analysis.

Integration with Relay Server
-----------------------------

The relay server can integrate these modules with minimal changes:

- Before placing an incoming envelope into the RAM-only mailbox, pass it through:
  - `MixRouter.schedule_envelope` to assign a delay.
  - Optional `TimingDefense` batching to group multiple envelopes.
- A background worker:
  - Periodically calls `CoverTrafficScheduler.maybe_generate_cover_packet` to inject cover traffic into the same routing path.
  - May use `make_dummy_envelope_like` to generate additional noise based on real traffic patterns.

What Metadata May Still Leak
----------------------------

- Recipient (`recipient_locator`), timing, and volume remain visible; delays and cover/dummy add noise only.
- A global passive adversary with precise timing can still correlate; this layer raises the bar for casual analysis.

Why This Is Not Tor or a Production Mixnet
------------------------------------------

- No onion routing, no multi-hop mixing, no formal anonymity set. Delays are configurable but not a provable mix design. Cover/dummy are best-effort; operational limitations apply.

