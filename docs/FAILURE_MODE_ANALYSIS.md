Failure Mode Analysis
=====================

This document describes key failure modes in GhostChat. For each: **symptoms**, **likely cause**, **security impact**, **detection path**, **recovery path**, **remaining risk**. Tied to the actual codebase.

1. Malformed or Truncated Envelope Input
----------------------------------------

**Symptoms:** `ValueError` or similar on `ProtocolEnvelope.from_dict()`, `SealedOuterEnvelope.from_dict()`, or `GroupMessage.from_dict()`; client or server log shows parse failure.

**Likely cause:** Truncated or corrupted network payload; attacker sending malformed JSON/dict; missing required fields or unsupported version.

**Security impact:** May cause message drop or exception; if parsing were to accept malformed data silently, could lead to undefined behavior or bypasses.

**Detection path:** Exception at parse site; logging of invalid input (without logging raw payload in production).

**Recovery path:** Drop the envelope; do not update session or replay state; optional alert for repeated malformed input from same source.

**Remaining risk:** Edge-case parsing bugs; no formal fuzzing; truncation could in theory split across field boundary (mitigated by required-field checks).

**Code:** `protocol/envelope.py`, `protocol/sealed_sender.py`, `group/group_message.py`.

2. Replay Cache Edge Cases
--------------------------

**Symptoms:** Legitimate message rejected as replay; or duplicate accepted when it should have been rejected (e.g., cache eviction or clock skew).

**Likely cause:** Replay cache key collision (theoretical); cache eviction policy discarding entry then same (sid, rk, n) reappears; multiple devices sharing same session id with unsynced replay state.

**Security impact:** False reject degrades availability; false accept could duplicate application-level effect or confuse state.

**Detection path:** User reports "message not received" or duplicate message; logs show `SessionReplayCache.accept` returning False or duplicate (sid, rk, n).

**Recovery path:** If false reject: consider session reset and re-handshake to clear replay view (loses in-flight ordering guarantees). If false accept: treat as protocol bug; no safe rollback of application state.

**Remaining risk:** Single-device replay cache has no cross-device binding; eviction policy may need tuning under load.

**Code:** `protocol/replay_protection.py`; `tests/test_replay_protection.py`.

3. Fork-Detection False Positives / Missed Cases
------------------------------------------------

**Symptoms:** Session marked for reset when no actual fork occurred (e.g., benign reorder); or fork not detected and divergent state accepted.

**Likely cause:** Reordering plus skipped-key window boundary; bug in `detect_fork` (e.g., comparing wrong pn/n); attacker sending crafted headers that pass fork check but corrupt state.

**Security impact:** False positive forces unnecessary reset (DoS/UX). Missed fork may allow acceptance of replayed or divergent messages.

**Detection path:** `mark_for_reset("fork-detected")` in logs; or decryption succeeding with inconsistent (n, pn) across peers.

**Recovery path:** On fork detection: discard session, re-handshake. If fork was missed: future decryption failures or consistency checks should eventually trigger reset or group resync.

**Remaining risk:** Heuristic fork detection may have edge cases; no cryptographic binding of "current" chain state to a single history.

**Code:** `protocol/fork_detection.py`, `protocol/session_reset.py`; `tests/test_fork_detection.py`, `tests/test_protocol_integration.py`.

4. Session Desynchronization
----------------------------

**Symptoms:** One side can encrypt, the other cannot decrypt (or vice versa); `DuplicateMessageError` or skipped-key errors on "fresh" messages; repeated decryption failures.

**Likely cause:** Lost or reordered messages beyond skipped-key window; concurrent send race; malicious reorder/replay; bug in ratchet step ordering.

**Security impact:** Conversation interruption; possible message loss; if not detected, could lead to inconsistent application state.

**Detection path:** Application-level catch of ratchet exceptions; session marked suspicious after repeated decryption failures.

**Recovery path:** Mark session suspicious; discard ratchet state; re-initiate X3DH with fresh prekeys; do not roll back chain keys.

**Remaining risk:** Aggressive reordering can exhaust skipped-key store and force reset; no in-band resync of ratchet state.

**Code:** `ratchet/double_ratchet.py`, `client/session_manager.py`; `tests/test_protocol_integration.py`.

5. Session Reset Triggering Conditions
--------------------------------------

**Symptoms:** `SessionResetState.needs_reset` true; caller told to re-handshake; session unusable until reset.

**Likely cause:** Replay or fork detected; or application explicitly requesting reset after repeated failures.

**Security impact:** Correct behavior (fail secure); reset prevents continued use of possibly compromised or inconsistent state.

**Detection path:** `mark_for_reset()` called from replay or fork logic; caller checks `reset_state.needs_reset` after decrypt failure.

**Recovery path:** Discard session state; perform new X3DH; establish new session; optionally notify peer out-of-band.

**Remaining risk:** Reset can be triggered by attacker (replay/fork) causing DoS; no rate limit on resets in prototype.

**Code:** `protocol/session_reset.py`, `client/session_manager.py`; `tests/test_protocol_integration.py`.

6. Relay Restart / Mailbox Loss
-------------------------------

**Symptoms:** Messages expected but not received; gaps in conversation or counters after relay restart.

**Likely cause:** RAM-only mailbox; relay process restart or crash; envelopes in queue at restart are lost.

**Security impact:** Availability and consistency; no confidentiality breach (relay never had keys).

**Detection path:** Clients observe missing messages or delivery timeouts; no server-side persistence to detect.

**Recovery path:** Accept loss of undelivered messages; application-level retry or acknowledgement for critical content; re-establish session if needed.

**Remaining risk:** No guaranteed delivery; no persistent queue in prototype.

**Code:** `server/router.py`, `server/mailbox.py`.

7. Delayed-Delivery Edge Cases
------------------------------

**Symptoms:** Message delivered much later than expected; order of delivery different from send order; timeout or user confusion.

**Likely cause:** Mix delay scheduling (`deliver_due`); high jitter; relay load; clock skew between relay and client.

**Security impact:** Mostly availability/UX; delayed delivery can interact with replay TTL (old envelope delivered late might be rejected as stale if replay window is time-bounded).

**Detection path:** Client-side delivery timestamps; operational monitoring of delay distribution.

**Recovery path:** Tune delay/jitter; ensure replay logic does not depend solely on wall-clock for "stale" (current implementation uses (sid, rk, n) and ordering, not just time).

**Remaining risk:** Very long delays could make replay cache retention policy relevant; no explicit TTL in replay cache in prototype.

**Code:** `network/mix_router.py`, `server/router.py` (`deliver_due`); `tests/test_mix_delay.py`.

8. Dummy / Cover Traffic Misclassification
------------------------------------------

**Symptoms:** Real message dropped as "undecryptable"; or dummy/cover processed as real (should not happen if dummies are not decryptable by any session).

**Likely cause:** Wrong session tried first; session not yet established for recipient; bug in `drop_undecryptable` path treating real as dummy; dummy encrypted with a key that accidentally matches a session (protocol bug).

**Security impact:** Real message loss (availability); or if dummy ever "decrypted", would be a serious protocol/implementation bug.

**Detection path:** User reports missing message; logs show envelope dropped in `recv_sealed(drop_undecryptable=True)`; or test that verifies real message not dropped when mixed with dummies.

**Recovery path:** Ensure only envelopes that fail all session keys are dropped; do not use drop_undecryptable for envelopes that might be for not-yet-established sessions without retry later.

**Remaining risk:** Session lookup order and timing can cause a real message to be dropped if session is missing or wrong; application should not treat "no message" as proof of "no send".

**Code:** `client/message_api.py` (`recv_sealed`), `network/dummy_packets.py`, `network/cover_traffic.py`; `tests/test_protocol_integration.py`, `tests/test_dummy_packets.py`.

9. Group State Divergence
-------------------------

**Symptoms:** Members disagree on epoch, membership list, or group hash; some can decrypt group messages others cannot; `verify_consistency` returns False.

**Likely cause:** Lost or misordered membership updates; partial apply of add/remove; malicious coordinator; bug in state distribution.

**Security impact:** Inconsistent view of who is in group; possible exclusion or inclusion of wrong members; stale epoch rejection prevents some cross-epoch decryption.

**Detection path:** `state_verification.verify_consistency`; `EpochManager.verify_state`; application-level comparison of membership and epoch.

**Recovery path:** Mark group resync required; obtain full GroupState from trusted member or quorum; verify hash and epoch; adopt and discard divergent local state.

**Remaining risk:** Single trusted source can push malicious but consistent state; no decentralized consensus in prototype.

**Code:** `group/state_verification.py`, `group/group_state.py`, `group/epoch_manager.py`; `tests/test_group_message_flow.py`, `tests/test_group_mls.py`.

10. Stale Epoch Delivery
-------------------------

**Symptoms:** Group message rejected with epoch mismatch; sender and recipient have different `state.epoch`.

**Likely cause:** Message from previous epoch delivered after epoch transition; replayed old group message; member removed and message from new epoch sent before they updated (they receive with old epoch).

**Security impact:** Correct rejection (removed member must not decrypt future epochs; new member must not decrypt prior epochs); avoids key confusion.

**Detection path:** `GroupMessenger.decrypt` raises `EpochMismatchError`; header.epoch != state.epoch.

**Recovery path:** Sender/recipient ensure they have latest group state; do not accept or process messages from wrong epoch.

**Remaining risk:** Application must handle epoch mismatch and optionally fetch latest state; no automatic state push on epoch change in prototype.

**Code:** `group/group_messenger.py`, `group/group_state.py`; `tests/test_group_message_flow.py`.

11. Invalid Member Add/Remove Update Handling
---------------------------------------------

**Symptoms:** Add or remove fails; inconsistent membership; member added but not receiving state; member removed but still has old state.

**Likely cause:** Invalid identity_pk; duplicate add; remove of non-member; coordinator bug or malicious coordinator; distribution failure.

**Security impact:** Group integrity; removed member might retain ability to decrypt if removal not applied everywhere; new member might not get key material.

**Detection path:** Exceptions from `add_member`/`remove_member`; `verify_consistency` after update; membership list comparison.

**Recovery path:** Validate identity and membership before apply; redistribute state to all current members; removed member must not receive new state (by design they are not in distribution list).

**Remaining risk:** Coordinator must be correct and trusted for membership; no multi-party validation in prototype.

**Code:** `group/membership.py`, `group/group_state.py`; `tests/test_group_state.py`, `tests/test_group_message_flow.py`.

12. Group Message Counter Inconsistency
---------------------------------------

**Symptoms:** Duplicate message accepted; or legitimate message rejected as duplicate; sender and recipient disagree on next counter.

**Likely cause:** Replay cache eviction; multiple sends with same counter (bug); reordered delivery and replay cache key (sender_leaf_index, counter) collision or misuse.

**Security impact:** Replay could duplicate application effect; false reject causes message loss.

**Detection path:** Group replay cache in `GroupMessenger.decrypt`; duplicate (sender_leaf_index, counter) rejected.

**Recovery path:** If duplicate accepted: treat as bug; no safe rollback. If false reject: resync group state or treat as unrecoverable for that message.

**Remaining risk:** Replay cache is per-recipient; no cross-member consistency guarantee for "max counter" in prototype.

**Code:** `group/group_messenger.py`; `tests/test_group_message_flow.py`.

13. Local State Corruption / Persistence Issues
------------------------------------------------

**Symptoms:** Deserialization failure on load; missing or truncated records; group hash or epoch check failure after load; identity or session missing.

**Likely cause:** OS/hardware failure during write; filesystem corruption; tampering with on-disk state; bug in serialize/deserialize.

**Security impact:** Data loss; possible desync if partial state applied; if tampering undetected, could lead to wrong keys or membership.

**Detection path:** Exceptions from storage/serialization; `EpochManager` or hash verification failure on load.

**Recovery path:** Load from known-good snapshot if available; otherwise emergency wipe and re-bootstrap; do not silently continue with corrupted state.

**Remaining risk:** No snapshotting or backup in prototype; secure deletion not guaranteed.

**Code:** `storage/encrypted_db.py`, serialization in `group/`, `ratchet/`, `protocol/`; design only.

14. Skipped-Key Exhaustion
--------------------------

**Symptoms:** `SkippedKeyStorageLimitError` when processing out-of-order messages; session unable to accept further out-of-order messages.

**Likely cause:** Adversarial reordering or injection of many headers; large gaps in message numbering; natural loss plus reorder exceeding window.

**Security impact:** DoS for that session; possible message loss if limit hit; no memory exhaustion because store is bounded.

**Detection path:** Exception from `SkippedKeyStore.add`; caller catches `SkippedKeyStorageLimitError`.

**Recovery path:** Treat session at-risk; notify user; reset session via new handshake or drop further out-of-order messages (accept partial loss). No safe unbounded acceptance.

**Remaining risk:** Adversary can force limit and trigger reset; window size is a tuning parameter.

**Code:** `ratchet/skipped_keys.py`, `ratchet/double_ratchet.py`; tests that exercise skipped-key path.

15. Identity Key Compromise
---------------------------

**Symptoms:** Sessions established without user recognition; peer identity fingerprint change; unexpected new sessions.

**Likely cause:** Device compromise; private key exfiltration; prekey bundle substitution (see attack surface).

**Security impact:** Attacker can impersonate identity; establish sessions as victim; read/send in victim’s name if they also compromise device.

**Detection path:** Out-of-band fingerprint comparison; UX that surfaces new sessions or key changes.

**Recovery path:** Mark identity untrusted; generate new keypair and prekeys; inform contacts out-of-band; invalidate sessions for old identity.

**Remaining risk:** No automatic key rotation or revocation in prototype; trust in distribution channel.

**Code:** `crypto/identity.py`, `client/session_manager.py`; operational/UX only.

16. General Guidelines
----------------------

- **Fail closed:** On ambiguous errors or suspected tampering, reject messages or states; do not continue silently.
- **No automatic rollback:** Do not revert to older epochs or keys; derive fresh secrets.
- **Log safely:** Log errors and transitions without plaintext or long-lived key material.
- **User-facing clarity:** When reset or wipe is required, warn clearly about security implications and data loss.

