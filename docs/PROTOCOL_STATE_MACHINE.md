# Protocol State Machine

This document describes the state machines implemented in GhostChat. It focuses on **states**, **events**, and **transitions** for identity, sessions, sealed sender, network hardening, and group lifecycle.

**Legend:** `[STATE]` – state; `-->` – transition; `event:` – trigger; `guard` – condition that must hold.

---

## 1. Identity Bootstrap

```text
[NO_IDENTITY]
  --(generate Ed25519 keypair, serialize)-->
[IDENTITY_READY]

[IDENTITY_READY]
  --(publish / store public key)-->
[IDENTITY_PUBLISHED]
```

- **Enforcement:** `crypto/identity.py` – `IdentityKeyPair.generate()`, serialization helpers.
- **Tests:** `tests/test_identity.py`.

---

## 2. Prekey Publication / Retrieval

```text
[IDENTITY_PUBLISHED]
  --(generate SPK, sign with IK; generate OPK batch)-->
[PREKEYS_GENERATED]

[PREKEYS_GENERATED]
  --(serialize bundle, publish or store)-->
[PREKEY_BUNDLE_PUBLISHED]

[PREKEY_BUNDLE_PUBLISHED]
  --(peer fetches bundle)-->
[PREKEY_BUNDLE_AVAILABLE]
  guard: verify_spk(identity) passes; OPK consumed at most once
```

- **Enforcement:** `crypto/prekeys.py` – `SignedPreKey.verify()`, `PreKeyBundle.consume_one_time_prekey()`.
- **Tests:** `tests/test_prekeys.py`.

---

## 3. One-to-One Session Establishment

```text
[PREKEY_BUNDLE_AVAILABLE]
  --(initiator: perform hybrid X3DH)-->
[HANDSHAKE_INITIATED]

[HANDSHAKE_INITIATED]
  --(responder: complete X3DH, verify classical+PQ match)-->
[SESSION_ESTABLISHED]
  guard: root_key equal on both sides; SPK verified
```

- **Enforcement:** `crypto/x3dh.py` – `perform_classical_x3dh_handshake`, `perform_hybrid_x3dh_handshake`.
- **Tests:** `tests/test_x3dh.py`. Session creation in tests: `client/session_manager.py` – `create_symmetric_session()` (test helper).

---

## 4. One-to-One Outbound Message Flow

```text
[SESSION_ESTABLISHED]
  --(encrypt plaintext)-->
[DR_ENCRYPT]
  --(CK_s None? -> DH ratchet step; then KDF_CK)-->
[DR_HEADER_CT_READY]
  --(wrap in ProtocolEnvelope or seal inner)-->
[ENVELOPE_READY]
  --(submit to relay / transport)-->
[MSG_SENT]
```

- **Enforcement:** `ratchet/double_ratchet.py` – `encrypt()`; `protocol/envelope.py` – `ProtocolEnvelope`; `protocol/sealed_sender.py` – `seal()`; `client/session_manager.py` – `encrypt_for()`, `encrypt_sealed()`.

---

## 5. One-to-One Inbound Message Flow

```text
[ENVELOPE_RECEIVED]
  --(parse outer: ProtocolEnvelope or SealedOuterEnvelope)-->
[PARSED]
  guard: version supported; required fields present
  --(if sealed: unseal with session key)-->
[INNER_RECOVERED]
  --(replay check: SessionReplayCache.accept)-->
[REPLAY_OK]
  guard: not duplicate (sid, rk, n); not stale n
  --(fork check: detect_fork)-->
[FORK_OK]
  guard: no regression in n or previous_chain_length
  --(ratchet decrypt)-->
[PLAINTEXT_READY]
```

- **Enforcement:** `protocol/replay_protection.py` – `SessionReplayCache.accept()`; `protocol/fork_detection.py` – `detect_fork()`; `client/session_manager.py` – `decrypt_from()`, `decrypt_sealed()`.

---

## 6. Replay / Fork / Reset Decision Points

```text
[REPLAY_CHECK]
  --(key in seen OR n < highest_by_ratchet)-->
[REJECT] --> mark_for_reset("replay-detected"); raise
  --(accept)-->
[FORK_CHECK]

[FORK_CHECK]
  --(detect_fork: n regressed OR pn regressed)-->
[REJECT] --> mark_for_reset("fork-detected"); raise
  --(ok)-->
[PROCEED_TO_DECRYPT]

[SESSION_RESET_REQUIRED]
  --(caller discards session, re-handshake)-->
[SESSION_ESTABLISHED]
```

- **Enforcement:** `protocol/replay_protection.py`, `protocol/fork_detection.py`, `protocol/session_reset.py` – `mark_for_reset()`, `SessionResetState.needs_reset`.
- **Tests:** `tests/test_replay_protection.py`, `tests/test_fork_detection.py`, `tests/test_protocol_integration.py` (replay triggers reset).

---

## 7. Sealed Sender Processing

**Sender:**

```text
[PLAINTEXT + RECIPIENT]
  --(ratchet encrypt)-->
  --(build InnerSenderPackage: sender_id, session_id, header, ciphertext)-->
  --(derive K_seal = HKDF(root_key, "ghostchat-sealed-sender-v1"))-->
  --(seal(inner, K_seal) -> sp)-->
  --(build SealedOuterEnvelope: recipient_locator, ttl, sp, pad)-->
[OUTER_SENT_TO_RELAY]
```

**Recipient:**

```text
[OUTER_RECEIVED]
  --(parse SealedOuterEnvelope.from_dict)-->
  --(for each session: try unseal(sp, K_seal))-->
[INNER_RECOVERED]  (one session succeeds)
  --(replay + fork checks on synthetic ProtocolEnvelope from inner)-->
  --(ratchet decrypt inner ciphertext)-->
[PLAINTEXT_READY]
```

- **Enforcement:** `protocol/sealed_sender.py` – `seal()`, `unseal()`, `SealedOuterEnvelope`; `client/session_manager.py` – `encrypt_sealed()`, `decrypt_sealed()`.
- **Tests:** `tests/test_sealed_sender.py`, `tests/test_protocol_integration.py`.

---

## 8. Network Hardening Flow Hooks

```text
[ENVELOPE_AT_RELAY]
  --(use_mix? schedule_envelope; else enqueue)-->
[SCHEDULED or QUEUED]

[SCHEDULED]
  --(deliver_due(now): deliver_at <= now)-->
[DELIVERED_TO_MAILBOX]

[CLIENT_SEND]
  --(optional: apply_jitter, batch_messages)-->
  --(optional: get_pending_cover_packets -> inject cover envelopes)-->
[SUBMIT_TO_RELAY]

[CLIENT_RECV]
  --(is_sealed_envelope? decrypt_sealed; drop_undecryptable for dummies/cover)-->
[APPLICATION_MSG or DROPPED]
```

- **Enforcement:** `network/mix_router.py` – `schedule_envelope()`; `server/router.py` – `enqueue_by_envelope(use_mix=True)`, `deliver_due()`; `network/cover_traffic.py` – `maybe_generate_cover_packet()`; `client/message_api.py` – `recv_sealed(drop_undecryptable=True)`.
- **Tests:** `tests/test_mix_delay.py`, `tests/test_cover_traffic.py`, `tests/test_dummy_packets.py`, `tests/test_protocol_integration.py`.

---

## 9. Group State Lifecycle

```text
[NO_GROUP]
  --(create_group(group_id, member_ids))-->
[GROUP_EPOCH_1]
  guard: INITIAL_EPOCH=1; tree root, application_key, group_hash derived

[GROUP_EPOCH_N]
  --(send group message)-->
[GROUP_EPOCH_N]  (counter advanced; state unchanged)

[GROUP_EPOCH_N]
  --(add_member / remove_member)-->
[GROUP_EPOCH_N+1]
  guard: new epoch_secret, application_key, group_hash; tree updated
```

- **Enforcement:** `group/group_state.py` – `GroupState.create()`, `add_member()`, `remove_member()`; `group/key_schedule.py` – `derive_epoch_secret`, `derive_application_key`, `derive_group_hash`.
- **Tests:** `tests/test_group_state.py`, `tests/test_group_mls.py`, `tests/test_group_message_flow.py`.

---

## 10. Group Epoch Transition Flow

```text
[GROUP_EPOCH_N]
  --(add_member(identity_pk, leaf_secret))-->
  [assign new leaf; set_leaf; epoch += 1; _rederive_group_secret]
  -->
[GROUP_EPOCH_N+1]

[GROUP_EPOCH_N]
  --(remove_member(identity_pk, replacement_secret))-->
  [overwrite leaf; epoch += 1; _rederive_group_secret]
  -->
[GROUP_EPOCH_N+1]
```

- New members receive only state at `epoch >= join_epoch`; they cannot decrypt prior-epoch messages (epoch check in `GroupMessenger.decrypt`).
- Removed members’ leaf is overwritten; they cannot derive future keys.

---

## 11. Group Membership Add/Remove Flow

**Add:**

```text
[CONTROLLER_STATE]
  --(add_member(identity_pk))-->
  [new leaf index; tree.set_leaf; epoch += 1; _rederive_group_secret]
  -->
[UPDATED_STATE]
  --(distribute state to new member only for join_epoch)-->
[NEW_MEMBER_JOINED]
```

**Remove:**

```text
[CONTROLLER_STATE]
  --(remove_member(identity_pk))-->
  [members.pop; tree.set_leaf(replacement); epoch += 1; _rederive_group_secret]
  -->
[UPDATED_STATE]
  --(distribute to remaining members; removed member not updated)-->
[MEMBER_REMOVED]
```

- **Enforcement:** `group/membership.py` – `MembershipController.add_member()`, `remove_member()`; `group/group_state.py` – `add_member()`, `remove_member()`.
- **Tests:** `tests/test_group_message_flow.py` (Dave cannot decrypt prior; Charlie cannot decrypt future).

---

## 12. Client Storage (Design)

```text
[STORAGE_UNINITIALIZED]
  --(open encrypted DB, derive local key)-->
[STORAGE_READY]

[STORAGE_READY]
  --(emergency wipe)-->
[STORAGE_WIPED]
  --(re-bootstrap)-->
[STORAGE_READY]
```

- **Enforcement:** Design in `storage/encrypted_db.py`; no plaintext session keys in long-term storage by design.
