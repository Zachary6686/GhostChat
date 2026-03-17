Attack Surface Analysis
=======================

This document enumerates the primary attack surfaces in GhostChat. For each surface: **entry point**, **realistic attacker actions**, **current defenses**, **residual risk**, and **relevant modules/tests**.

1. Client Bootstrap / Identity Handling
---------------------------------------

**Entry point:** Identity key generation, serialization, and publication; first-use trust.

**Attacker actions:** Supply or substitute identity material during bootstrap; trick client into trusting a wrong identity; exfiltrate or corrupt identity before publication.

**Defenses:** Identity generated locally; SPK bound to IK and verified before use; no automatic trust of remote identity without verification.

**Residual risk:** Distribution channel for public identity/SPK may be unauthenticated; no TOFU or key pinning in prototype.

**Modules/tests:** `crypto/identity.py`, `client/session_manager.py`; `tests/test_identity.py`.

2. Prekey Distribution Surface
------------------------------

**Entry point:** Publication and retrieval of prekey bundles (IK, SPK, OPKs) via directory or relay.

**Attacker actions:** Substitute SPK or OPKs to mount MITM during X3DH; replay old bundles; exhaust OPKs to force fallback or failure.

**Defenses:** SPK signed with Ed25519 IK and verified by peers; OPKs consumed once; `OneTimePreKeyExhaustedError` on depletion.

**Residual risk:** Malicious directory can substitute entire bundle (including identity); trust in distribution channel required.

**Modules/tests:** `crypto/prekeys.py`, `crypto/x3dh.py`; `tests/test_prekeys.py`, `tests/test_x3dh.py`.

3. Handshake / Session Establishment Surface
---------------------------------------------

**Entry point:** X3DH handshake execution (classical and PQ components); session key derivation.

**Attacker actions:** MITM by altering DH or PQ components; downgrade to classical-only; inject invalid handshake material.

**Defenses:** Handshake asserts matching classical and PQ secrets; SPK verification binds to identity; no silent downgrade.

**Residual risk:** PQ backend is placeholder; MITM possible if prekey bundle is substituted (see prekey surface).

**Modules/tests:** `crypto/x3dh.py`, `client/session_manager.py`; `tests/test_x3dh.py`.

4. Envelope Parsing / Serialization Surface
------------------------------------------

**Entry point:** `ProtocolEnvelope.from_dict()`, `SealedOuterEnvelope.from_dict()`, `GroupMessage.from_dict()`; JSON/dict inputs from network or storage.

**Attacker actions:** Send malformed or truncated envelopes; wrong types, missing fields, invalid version; trigger exceptions or undefined behavior.

**Defenses:** Version checks; required-field validation; `ValueError` on invalid input; no silent acceptance of malformed data.

**Residual risk:** Parsing bugs could still exist for edge cases; no formal fuzzing in prototype.

**Modules/tests:** `protocol/envelope.py`, `protocol/sealed_sender.py`, `group/group_message.py`; `tests/test_protocol_envelope.py`, `tests/test_sealed_sender.py`.

5. Replay Injection / Duplication
----------------------------------

**Entry point:** Inbound one-to-one and group messages; replayed or duplicated envelopes.

**Attacker actions:** Replay a previously seen message; duplicate (sid, rk, n) or (sender_leaf_index, counter) to probe state or cause reset.

**Defenses:** `SessionReplayCache` rejects duplicate (session_id, ratchet_key, n) and stale n; group replay cache on (sender_leaf_index, counter); replay/fork mark session for reset.

**Residual risk:** Replay can force session reset (DoS); no cross-device replay binding.

**Modules/tests:** `protocol/replay_protection.py`, `client/session_manager.py`, `group/group_messenger.py`; `tests/test_replay_protection.py`, `tests/test_protocol_integration.py`.

6. Fork / Desynchronization / Stale State Attacks
-------------------------------------------------

**Entry point:** Out-of-order or divergent ratchet headers; regressed message numbers or previous_chain_length.

**Attacker actions:** Inject headers that regress n or pn to trigger fork detection or desync; cause one side to accept state that the other rejects.

**Defenses:** `detect_fork()` before decryption; `mark_for_reset()` on fork; no blind decryption after fork signal; session reset required.

**Residual risk:** Fork can force reset (DoS); aggressive reordering may exhaust skipped-key store.

**Modules/tests:** `protocol/fork_detection.py`, `protocol/session_reset.py`, `client/session_manager.py`; `tests/test_fork_detection.py`, `tests/test_protocol_integration.py`.

7. Sealed Sender Metadata Handling
-----------------------------------

**Entry point:** Outer envelope fields (recipient_locator, ttl, sp, pad); relay routing and delivery.

**Attacker actions:** Correlate recipient with timing/size; infer sender from routing if sealed sender is not used; tamper with outer fields to affect delivery.

**Defenses:** Outer envelope omits sender_id/session_id; routing uses only recipient_locator; relay does not decrypt; padding and mix/cover reduce correlation.

**Residual risk:** Size and timing still observable; no padding normalization; metadata hardening is best-effort.

**Modules/tests:** `protocol/sealed_sender.py`, `server/router.py`; `tests/test_sealed_sender.py`, `tests/test_protocol_integration.py`.

8. Relay Routing Surface
------------------------

**Entry point:** WebSocket delivery; `enqueue_by_envelope`, `deliver_due`, `get_routing_recipient`; mailbox storage.

**Attacker actions:** Flood relay; inject envelopes to wrong mailboxes if routing key is predictable; exhaust mailbox memory.

**Defenses:** Payload-blind routing; TTL and mailbox limits; no decryption on server.

**Residual risk:** DoS via volume; routing key guessing if locator space is small.

**Modules/tests:** `server/router.py`, `server/mailbox.py`; integration tests.

9. Delayed Routing / Dummy / Cover Traffic Surface
--------------------------------------------------

**Entry point:** Mix delay scheduling; cover and dummy packet generation; client send/recv paths that inject or drop traffic.

**Attacker actions:** Distinguish real from dummy/cover by size or timing; abuse delayed delivery to reorder or drop; trigger misclassification (treat real as dummy).

**Defenses:** Undecryptable envelopes dropped with `drop_undecryptable=True` without updating session state; delayed delivery does not alter content; cover/dummy not used for session state.

**Residual risk:** Real message misclassified as undecryptable (e.g., wrong session) drops message; timing/size analysis still possible.

**Modules/tests:** `network/mix_router.py`, `network/cover_traffic.py`, `network/dummy_packets.py`, `client/message_api.py`; `tests/test_mix_delay.py`, `tests/test_cover_traffic.py`, `tests/test_dummy_packets.py`, `tests/test_protocol_integration.py`.

10. Group State Update Surface
------------------------------

**Entry point:** Add/remove member; epoch transition; distribution of new group state.

**Attacker actions:** Divergent membership or epoch across clients; malicious coordinator omitting members; inject stale or forged state.

**Defenses:** Group hash commits to group_id, epoch, membership, root; `verify_consistency`; epoch monotonicity; new/removed member key derivation prevents past/future decryption.

**Residual risk:** Single malicious coordinator can push consistent but attacker-chosen state if all rely on it.

**Modules/tests:** `group/group_state.py`, `group/membership.py`, `group/state_verification.py`; `tests/test_group_state.py`, `tests/test_group_mls.py`, `tests/test_group_message_flow.py`.

11. Malformed Group Messages / Stale Epoch Injection
-----------------------------------------------------

**Entry point:** Inbound group messages; epoch, sender_leaf_index, counter in headers.

**Attacker actions:** Send message with wrong epoch; unknown leaf index; replayed (leaf, counter); malformed payload.

**Defenses:** `GroupMessenger.decrypt` rejects epoch mismatch, unknown leaf, duplicate (leaf, counter); `GroupMessage.from_dict()` validates structure.

**Residual risk:** Application must bind leaf index to identity; no per-message signature in prototype.

**Modules/tests:** `group/group_messenger.py`, `group/group_message.py`; `tests/test_group_message_flow.py`, `tests/test_group_mls.py`.

12. Storage Compromise / Local Database Theft
---------------------------------------------

**Entry point:** Encrypted local DB; serialized identities, sessions, group states on disk.

**Attacker actions:** Steal device and DB; extract encryption key (e.g., from memory or keychain); tamper with serialized state to cause desync.

**Defenses:** Encrypted storage abstraction; no plaintext session keys in long-term storage by design; hashes/epochs detect many tampering forms; forward secrecy limits value of old state.

**Residual risk:** If storage key is compromised, all local state is readable; no secure deletion guarantee in prototype.

**Modules/tests:** `storage/encrypted_db.py`; design only; no dedicated storage compromise tests.

13. Denial-of-Service and State-Exhaustion Risks
------------------------------------------------

**Entry point:** Relay connections; handshake attempts; session resets; skipped-key cache; replay caches; group size and epoch churn.

**Attacker actions:** Flood relay or mailboxes; force many handshakes or resets; exhaust OPKs; exhaust skipped-key store; spam group updates.

**Defenses:** TTLs, size limits, mailbox limits; bounded SkippedKeyStore with explicit error; replay/fork trigger reset (no silent growth); error thresholds and backoff (design).

**Residual risk:** DoS by forcing resets or exhausting caches; no rate limiting or cost in prototype.

**Modules/tests:** `server/router.py`, `ratchet/skipped_keys.py`, `protocol/replay_protection.py`; `tests/test_replay_protection.py`, `tests/test_fork_detection.py`.

14. Network Entry Points (Relay and Mix)
----------------------------------------

### 14.1 Relay WebSocket Interface

**Entry point:** Client connections and inbound frames (sealed-sender envelopes, control).

**Attacker actions:** TLS downgrade/MITM if misconfigured; flooding; large or malformed envelopes to trigger parsing or resource exhaustion.

**Defenses:** TLS assumed correct; server treats payloads as opaque; RAM-only mailbox with TTL; envelope size/lifetime can be bounded.

**Residual risk:** Operational TLS and deployment hardening are out of scope for prototype.

### 14.2 Envelope Routing and Mix Layer

**Entry point:** Scheduling and forwarding of envelopes; mix delays and jitter.

**Attacker actions:** Timing analysis; distinguish cover/dummy from real traffic.

**Defenses:** Mix delays and jitter; cover and dummy traffic; relay does not inspect payload.

**Residual risk:** Strong traffic analysis possible; no formal anonymity guarantees.

15. Summary
-----------

Primary surfaces: client bootstrap and identity; prekey distribution; handshake/session establishment; envelope parsing/serialization; replay and fork/desync; sealed sender metadata; relay routing; delayed/dummy/cover traffic; group state updates; malformed group messages and stale epoch; storage compromise; DoS and state exhaustion; network (relay and mix).

Defenses: identity and SPK verification; OPK single-use; replay and fork detection with reset; malformed envelope rejection; payload-blind relay; sealed sender outer envelope; bounded caches and TTLs; group hash and epoch verification; encrypted storage design.

The system is a research prototype and does not claim resistance to powerful global adversaries or formal anonymity guarantees.

