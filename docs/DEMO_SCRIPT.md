# Demo Script

This script describes a **test-driven demonstration** of GhostChat using the current implementation. The primary runnable artifact is the test suite; each step maps to tests and the security property demonstrated.

## Prerequisites

```bash
cd ghostchat
pip install -r requirements.txt
```

## 1. Start relay (in-memory)

The tests use an **in-memory transport** and optional **relay router**; no separate server process is required. For a live relay demo you would start the WebSocket server (if implemented) in a separate terminal.

**What to run:** Tests that use `server.router` or in-memory mailboxes (e.g. `test_protocol_integration.py`, `test_sealed_sender.py`).

**Expected behavior:** Envelopes are enqueued and delivered via the in-memory router; `deliver_due(now)` used where mix delay is tested.

**Security property:** Relay is payload-blind; routing by `recipient_locator` only.

---

## 2. Bootstrap Alice and Bob

Identity and prekeys are created in test setup: Ed25519 identity, X25519 SPK (signed with IK), OPKs.

**What to run:**

```bash
python -m python -m pytest tests/test_identity.py tests/test_prekeys.py -v
```

**Expected behavior:** Identity keypairs and prekey bundles generate and verify; SPK validates under identity.

**Security property:** Identity key binding; SPK must validate under claimed identity before trust.

---

## 3. Establish one-to-one session

Hybrid X3DH handshake establishes a shared root key; double ratchet is initialized.

**What to run:**

```bash
python -m python -m pytest tests/test_x3dh.py tests/test_ratchet_basic.py -v
```

**Expected behavior:** Both sides derive the same root key; ratchet encrypt/decrypt succeeds in order and out of order (within skipped-key window).

**Security property:** Session establishment with authenticated SPK; forward secrecy and post-compromise security from ratchet.

---

## 4. Send encrypted one-to-one message

End-to-end encrypted send/receive via session manager and (in integration) sealed sender.

**What to run:**

```bash
python -m python -m pytest tests/test_protocol_integration.py::test_protocol_integration_end_to_end tests/test_sealed_sender.py -v
```

**Expected behavior:** Message encrypted, wrapped in envelope (or sealed), delivered via router, decrypted at recipient.

**Security property:** Confidentiality and integrity; relay sees only opaque envelope.

---

## 5. Show replay rejection

Replayed message is rejected and session is marked for reset.

**What to run:**

```bash
python -m python -m pytest tests/test_replay_protection.py tests/test_protocol_integration.py::test_protocol_integration_replay_triggers_reset -v
```

**Expected behavior:** Duplicate (session_id, ratchet_key, n) rejected; `mark_for_reset` called; `needs_reset` true.

**Security property:** One-to-one replayed messages must be rejected; protocol inconsistency surfaces before blind decryption.

---

## 6. Sealed sender relay behavior

Relay routes by recipient only; sender identity and session metadata are inside sealed payload.

**What to run:**

```bash
python -m python -m pytest tests/test_sealed_sender.py tests/test_protocol_integration.py::test_sealed_sender_via_relay_router tests/test_protocol_integration.py::test_sealed_sender_and_plain_both_work -v
```

**Expected behavior:** Sealed outer envelope contains only recipient_locator, ttl, sp, pad; relay does not see sender_id/session_id; recipient unseals and decrypts.

**Security property:** Relay does not require plaintext sender identity in sealed sender mode; payload-blind routing.

---

## 7. Delayed / dummy / cover traffic (high level)

Mix delay, cover traffic, and dummy packets are exercised; undecryptable envelopes are dropped without corrupting session state.

**What to run:**

```bash
python -m python -m pytest tests/test_mix_delay.py tests/test_cover_traffic.py tests/test_dummy_packets.py tests/test_network_cover_and_dummy.py tests/test_network_mix_and_timing.py -v
```

**Expected behavior:** Envelopes scheduled with delay; cover/dummy generated; when real and dummy/cover are mixed, real message is still decrypted and dummy/cover dropped without updating replay/fork state.

**Security property:** Delayed/dummy/cover traffic must not corrupt real session state.

---

## 8. Create Alice/Bob/Charlie group

Group created with epoch 1; tree and application key derived.

**What to run:**

```bash
python -m python -m pytest tests/test_group_state.py tests/test_group_message_flow.py::test_create_group_alice_bob_charlie -v
```

**Expected behavior:** `MembershipController.create_group` produces state with epoch ≥ 1, three members, group_id, application_key, group_hash.

**Security property:** Group state lifecycle; epoch starts at 1; group hash commits to membership and root.

---

## 9. Send group message

Message encrypted with group application key; recipients decrypt with same epoch state.

**What to run:**

```bash
python -m python -m pytest tests/test_group_message_flow.py::test_send_valid_group_message_decrypt_at_recipients -v
```

**Expected behavior:** `send_group_text` / `recv_group_text` deliver plaintext; epoch and replay checks pass.

**Security property:** Group confidentiality; replay cache (sender_leaf_index, counter).

---

## 10. Add Dave; verify Dave cannot read older epoch traffic

Epoch rotates on add; new member receives state only for join epoch; messages from prior epoch rejected.

**What to run:**

```bash
python -m python -m pytest tests/test_group_message_flow.py::test_add_dave_epoch_rotates_dave_cannot_decrypt_prior -v
```

**Expected behavior:** After add_member, epoch increments; Dave’s state is for new epoch only; message from previous epoch raises EpochMismatchError when Dave tries to decrypt.

**Security property:** Newly added group members must not decrypt prior epochs.

---

## 11. Remove Charlie; verify Charlie cannot read newer epoch traffic

Leaf overwritten; epoch rotated; Charlie not given new state; message from new epoch fails for Charlie.

**What to run:**

```bash
python -m python -m pytest tests/test_group_message_flow.py::test_remove_charlie_epoch_rotates_charlie_cannot_decrypt_future -v
```

**Expected behavior:** After remove_member, Charlie’s local state is stale; message from new epoch fails to decrypt (epoch mismatch or wrong key).

**Security property:** Removed group members must not decrypt future epochs.

---

## 12. Stale epoch rejection / group consistency protection

Message with wrong epoch rejected; group hash / state verification detects divergence.

**What to run:**

```bash
python -m python -m pytest tests/test_group_message_flow.py tests/test_group_epoch.py tests/test_group_mls.py -v
```

**Expected behavior:** Decrypt with `header.epoch != state.epoch` raises EpochMismatchError; state verification rejects inconsistent state; replayed (sender_leaf_index, counter) rejected.

**Security property:** Stale or divergent group state must not be accepted silently.

---

## Full demo (single run)

Run the full test suite to demonstrate all of the above in one go:

```bash
python -m pytest tests/ -v
```

For a focused “security highlights” run:

```bash
python -m python -m pytest tests/test_protocol_integration.py tests/test_sealed_sender.py tests/test_replay_protection.py tests/test_fork_detection.py tests/test_group_message_flow.py tests/test_group_mls.py tests/test_group_epoch.py tests/test_mix_delay.py tests/test_cover_traffic.py tests/test_dummy_packets.py -v
```

---

## Optional: CLI or interactive demo

If a CLI or interactive client is added later, the same flows can be run manually: start relay, bootstrap profiles, handshake, send/recv pairwise and group messages, add/remove members, and observe replay/stale-epoch rejection. The test suite remains the authoritative specification of expected behavior and security properties.
