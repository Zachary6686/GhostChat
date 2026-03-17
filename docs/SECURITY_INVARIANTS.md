Security Invariants
===================

This document lists key security invariants that GhostChat maintains, where they are enforced, and which tests cover them. It does not prove completeness but supports reasoning about protocol safety.

Notation
--------

- `IK` – identity key (Ed25519).
- `SPK` – signed pre-key (X25519).
- `OPK` – one-time pre-key (X25519).
- `RK` – ratchet root key.
- `CK_s`, `CK_r` – sending/receiving chain keys.
- `MK` – per-message key.
- `GE` – group epoch.
- `GK` – group epoch secret.
- `AK` – group application key.

1. Identity and Pre-Key Invariants
----------------------------------

**Invariant 1.1 – Identity key binding must verify before trust is established**

- **Why it matters:** Trust in a peer’s keys depends on binding SPK (and thus the handshake) to a verified identity.
- **Where enforced:** `crypto.prekeys.SignedPreKey.verify(identity)`; `PreKeyBundle.verify_spk()`. Handshake code uses verified bundle only.
- **Tests:** `tests/test_prekeys.py` (SPK verification).
- **Limitations:** Distribution channel for identity/SPK must be trusted or separately authenticated; no TOFU/pinning in prototype.

**Invariant 1.2 – Signed prekeys must validate under the claimed identity**

- Every `SPK` is signed by the corresponding `IK` and verified before use.
- **Where enforced:** `crypto.prekeys.SignedPreKey.verify(identity)` and `PreKeyBundle.verify_spk()`.
- **Tests:** `tests/test_prekeys.py`.

**Invariant 1.3 – One-time prekeys must not be reused**

- Each `OPK` is consumed at most once during X3DH.
- **Where enforced:** `PreKeyBundle.consume_one_time_prekey()` removes the OPK from the pool; `OneTimePreKeyExhaustedError` on depletion.
- **Tests:** `tests/test_prekeys.py`.

2. Handshake and Root Key Invariants
------------------------------------

**Invariant 2.1 – Shared root equivalence**

- After a successful hybrid X3DH, both initiator and responder must derive the same root key.
- Enforced by:
  - `crypto.x3dh.perform_classical_x3dh_handshake` and `perform_hybrid_x3dh_handshake` assert equality of classical and PQ components before returning `X3DHSessionSecrets`.

**Invariant 2.2 – PQ component included when configured**

- When a PQ backend is used, `GK` / `RK` MUST be derived from `classical_secret || pq_secret`.
- Enforced by:
  - `_derive_root_key` in `crypto.x3dh` that concatenates classical and PQ shared secrets when PQ is present.

3. Double Ratchet Invariants
----------------------------

**Invariant 3.1 – Message keys are single-use**

- Each `MK` is derived once from a chain key and not reused.
- Enforced by:
  - `kdf_chain()` producing `(CK', MK)` with CK updated immediately in `DoubleRatchet.encrypt` and `DoubleRatchet.decrypt`.
  - Message keys are not stored beyond transient use, except in the bounded skipped-key cache.

**Invariant 3.2 – Chain keys advance monotonically**

- `CK_s` and `CK_r` can only move forward; they are never reset to an earlier value.
- Enforced by:
  - No API to decrement message counters or re-insert older chain keys.
  - Ratchet state transitions (`_dh_ratchet_receive`, `_dh_ratchet_step`) always derive new root and chain keys.

**Invariant 3.3 – Skipped keys are bounded**

- The cache of skipped message keys has a fixed maximum size.
- Enforced by:
  - `SkippedKeyStore(max_keys=...)` raises `SkippedKeyStorageLimitError` when the capacity is exceeded.
  - Callers must treat this as an error and potentially reset or resync.

**Invariant 3.4 – Replays in current chain rejected**

- Messages with `(ratchet_pub, n)` already processed are rejected.
- Enforced by:
  - `DoubleRatchet.decrypt` raises `DuplicateMessageError` when `h.n < Nr`.

4. Group Messaging Invariants
-----------------------------

**Invariant 4.1 – Epoch monotonicity**

- Group epoch numbers `GE` must increase (or stay equal locally) on membership changes; they must not decrease.
- Enforced by:
  - `GroupState.add_member` and `remove_member` increment `epoch` on each operation.
  - `verify_consistency` in `group.state_verification` checks `epoch >= previous_epoch` when provided.

**Invariant 4.2 – Newly added group members must not decrypt prior epochs**

- **Why it matters:** Join does not grant access to past group traffic.
- **Where enforced:** `GroupMessenger.decrypt` rejects when `header.epoch != state.epoch`; new members only receive state for join epoch or later.
- **Tests:** `tests/test_group_state.py`, `tests/test_group_message_flow.py` (Dave cannot decrypt prior).

**Invariant 4.3 – Removed members must not decrypt future epochs**

- **Why it matters:** Ensures removal is cryptographically enforced.
- **Where enforced:** `GroupState.remove_member` overwrites the removed member’s leaf with a fresh secret and recomputes tree root and epoch secret; removed member has no new state.
- **Tests:** `tests/test_group_state.py`, `tests/test_group_mls.py`, `tests/test_group_message_flow.py` (Charlie cannot decrypt future).

**Invariant 4.4 – Group hash matches membership and root**

- `group_hash` must commit to `group_id`, `epoch`, membership list, and tree root.
- Enforced by:
  - `derive_group_hash()` in `group.key_schedule`.
  - `GroupState._rederive_group_secret` recomputes `group_hash` whenever membership or epoch changes.
  - `state_verification.verify_consistency` compares group hashes across peers.

**Invariant 4.5 – Group message replay rejection**

- Duplicate group messages from the same sender with the same counter are rejected.
- Enforced by:
  - `GroupMessenger`’s `ReplayCache` keyed by `(sender_leaf_index, counter)` and enforced in `decrypt()`.

5. Replay and Envelope Invariants
---------------------------------

**Invariant 5.1 – Network-level duplicates are bounded**

- The relay does not attempt to decrypt payloads but should not indefinitely retain envelopes.
- Enforced by:
  - TTL fields respected in mailbox logic (RAM-only store).
  - Expired envelopes are dropped rather than redelivered.

**Invariant 5.2 – One-to-one replayed messages must be rejected**

- **Why it matters:** Prevents replay from being accepted as a new message and avoids state corruption.
- **Where enforced:** `protocol.replay_protection.SessionReplayCache`, keyed by `(session_id, sender_ratchet_key, message_number)`; rejection before ratchet decryption in `session_manager.decrypt_from()` / `decrypt_sealed()`.
- **Tests:** `tests/test_replay_protection.py`, `tests/test_protocol_integration.py` (replay triggers reset).

**Invariant 5.2b – Malformed envelopes must not be accepted silently**

- **Why it matters:** Silent acceptance of malformed data can hide attacks or cause undefined behavior.
- **Where enforced:** `ProtocolEnvelope.from_dict()` and `SealedOuterEnvelope.from_dict()` raise `ValueError` on missing/invalid fields or version; `GroupMessage.from_dict()` raises on malformed payload.
- **Tests:** `tests/test_protocol_envelope.py`, `tests/test_sealed_sender.py` (malformed rejected).

**Invariant 5.2c – Fork/inconsistency signals must surface before blind decryption**

- **Where enforced:** Replay and fork checks run in `decrypt_from()` and `decrypt_sealed()` before `ratchet.decrypt()`; `mark_for_reset()` on replay/fork.
- **Tests:** `tests/test_fork_detection.py`, `tests/test_protocol_integration.py`.

**Invariant 5.2d – Session reset must surface on protocol inconsistency**

- **Where enforced:** `protocol.session_reset.SessionResetState`; `mark_for_reset()` called when replay or fork is detected; caller can inspect `reset_state.needs_reset`.
- **Tests:** `tests/test_protocol_integration.py` (replay triggers reset and needs_reset).

**Invariant 5.3 – Application-level replay rejection**

- Pairwise and group messaging layers also enforce replay protection on their own headers.
- Enforced by:
  - Double ratchet’s skipped-key store and `DuplicateMessageError`.
  - Group messaging replay cache keyed by `(sender_leaf_index, counter)`.

6. Storage and Key Lifecycle Invariants
---------------------------------------

**Invariant 6.1 – No plaintext session keys in long-term storage**

- Long-term storage should contain encrypted session state only.
- Enforced by:
  - Separation of encryption logic in `storage/encrypted_db.py` (by design).
  - Session materials are serialized and stored through this abstraction, not written as plaintext files.

**Invariant 6.2 – Emergency wipe removes local cryptographic material**

- A local wipe operation must delete stored identity/session/group keys.
- Enforced by:
  - Wipe API in storage layer (design requirement).
  - Callers treat wipe as terminal; re-bootstrap is required.

7. Network Hardening Invariants
-------------------------------

**Invariant 7.1 – Relay must remain payload-blind**

- **Why it matters:** Prevents server from reading or tampering with message content.
- **Where enforced:** Protocol design: relay has no decryption routines; only opaque envelopes are stored and forwarded; `server/router.py` routes by `recipient_locator` only.
- **Tests:** `tests/test_protocol_integration.py`, `tests/test_sealed_sender.py`.
- **Limitations:** Relay can still observe size, timing, and routing; no padding normalization in prototype.

**Invariant 7.3 – Relay must not require plaintext sender identity in sealed sender mode**

- **Why it matters:** Hides who is talking to whom from the relay.
- **Where enforced:** `SealedOuterEnvelope` contains only `recipient_locator`, `ttl`, `sp`, `pad`; `get_routing_recipient(envelope)` uses only `recipient_locator` (or legacy `recipient`); no sender field required for delivery.
- **Tests:** `tests/test_sealed_sender.py`, `tests/test_protocol_integration.py`.

**Invariant 7.2 – Optional hardening is best-effort only**

- Mix delays, cover traffic, dummy packets, and timing jitter must not change cryptographic semantics.
- Enforced by:
  - Network hardening primitives operate on opaque envelopes; they do not inspect or alter inner payloads beyond timing and random padding.
  - All cryptographic verification continues to happen at endpoints.

**Invariant 7.4 – Delayed/dummy/cover traffic must not corrupt real session state**

- **Why it matters:** Hardening must not break correctness of real sessions.
- **Where enforced:** `recv_sealed(drop_undecryptable=True)` drops undecryptable envelopes without updating replay/fork state; `deliver_due()` only moves envelopes, does not alter content; routing uses `recipient_locator` only.
- **Tests:** `tests/test_protocol_integration.py` (mixed real + dummy + cover), `tests/test_dummy_packets.py`, `tests/test_mix_delay.py`.

8. Error Handling and Desync Invariants
---------------------------------------

**Invariant 8.1 – Detection over silent corruption**

- When state inconsistencies are detected, the system prefers explicit failure over silent continuation.
- Enforced by:
  - Exceptions such as `InvalidSignatureError`, `OneTimePreKeyExhaustedError`, `DuplicateMessageError`, `SkippedKeyStorageLimitError`.
  - Group state verification returning `False` on mismatch, prompting resync rather than continuing with divergent views.
  - Protocol-level replay and fork detection marking sessions for reset when inconsistencies are observed.

**Invariant 8.2 – No rollback to older epochs/sessions**

- Recovery flows must not silently revert to a stale `RK` or `GE`.
- **Where enforced:** `EpochManager`; `SessionResetState` and `mark_for_reset`; no API to decrement epoch or re-insert old keys.
- **Tests:** `tests/test_group_epoch.py`, `tests/test_protocol_integration.py`.

**Invariant 8.3 – Stale or divergent group state must not be accepted silently**

- **Why it matters:** Prevents inconsistent group view and key confusion.
- **Where enforced:** `GroupMessenger.decrypt` raises `EpochMismatchError` for wrong epoch; `state_verification.verify_consistency` and `validate_serialized`; deserialize validates before loading.
- **Tests:** `tests/test_group_message_flow.py` (stale epoch rejected, group hash divergence), `tests/test_group_mls.py`.

