Security Review Checklist
=========================

This checklist is intended for internal and external reviewers to systematically assess GhostChat’s security properties. It is organized by subsystem and focuses on correctness, misuse resistance, and operational risks.

1. Key Lifecycle
----------------

- [ ] **Identity keys**
  - [ ] Ed25519 identity keys are generated using a secure RNG.
  - [ ] Identity private keys are never transmitted over the network.
  - [ ] Identity public keys are treated as stable identifiers and pinned where appropriate.
- [ ] **Identity binding**
  - [ ] Trust is established only after identity key binding is verified (SPK verified under claimed IK).
  - [ ] No use of unverified prekey material for handshake.
- [ ] **Pre-keys**
  - [ ] SPKs are always signed by the corresponding identity key.
  - [ ] Signature verification is mandatory before accepting SPKs.
  - [ ] OPKs are consumed at most once and removed from the pool after use.
  - [ ] There is a strategy for refreshing pre-key bundles (rotation over time).
- [ ] **Ratchet keys**
  - [ ] Per-session ratchet keys are derived only from the intended inputs (no mixing of unrelated secrets).
  - [ ] Old ratchet keys are erased when no longer needed.
- [ ] **Group keys**
  - [ ] Group epoch secrets and application keys are regenerated on every membership change.
  - [ ] Old epoch keys are not reused or reintroduced.

2. Nonce and AEAD Handling
--------------------------

- [ ] **Per-message nonces**
  - [ ] Nonce derivation functions use sufficient entropy and uniqueness (e.g., derived from message key and counter).
  - [ ] There is no reuse of AEAD nonces with the same key.
- [ ] **Associated data**
  - [ ] Headers (session or group) are always included as AEAD associated data.
  - [ ] Changes in headers (e.g., epoch, counters) will cause authentication failures if tampered with.
- [ ] **Cipher selection**
  - [ ] A modern AEAD (e.g., ChaCha20-Poly1305) is used consistently.
  - [ ] There are no custom or ad-hoc cipher constructions.

3. Replay and Ordering
----------------------

- [ ] **Replay protection**
  - [ ] Pairwise: `SessionReplayCache` rejects duplicate (sid, rk, n) and stale n before ratchet decrypt.
  - [ ] Fork/reset: fork detection runs before decryption; session reset surfaces on replay/fork.
- [ ] **Pairwise sessions**
  - [ ] Messages with `(ratchet_pub, message_number)` already processed are detected and rejected.
  - [ ] Skipped message keys are used once then erased from the cache.
  - [ ] The size of the skipped-key cache is bounded and errors are handled explicitly.
- [ ] **Group sessions**
  - [ ] Group messages carry `(group_id, epoch, sender_leaf_index, counter)`.
  - [ ] Duplicate `(sender_leaf_index, counter)` pairs are rejected.
  - [ ] Old epochs are rejected (epoch mismatch).

4. Serialization and Parsing
----------------------------

- [ ] **Versioning**
  - [ ] All serialized cryptographic objects include version identifiers.
  - [ ] Unknown versions are rejected with clear errors.
- [ ] **Field validation**
  - [ ] Required fields are validated for presence and type.
  - [ ] Unexpected extra fields are either ignored safely or fail validation.
- [ ] **Deserialization safety**
  - [ ] No unsafe or implicit deserialization mechanisms (e.g., pickle).
  - [ ] Deserialization errors are surfaced and cannot be silently ignored.

5. Malformed Message Handling
-----------------------------

- [ ] **Handshake correctness**
  - [ ] Handshake messages: invalid signatures or malformed DH values result in handshake abort.
  - [ ] Hybrid X3DH rejects mismatched classical and PQ secrets; root key equivalence asserted.
- [ ] **Session messages**
  - [ ] Malformed headers or invalid counters result in session-level errors.
  - [ ] Such errors are treated as suspicious (potential desync or attack).
- [ ] **Group messages**
  - [ ] Invalid group_id or epoch are rejected early.
  - [ ] Unknown leaf indices are treated as invalid membership.

6. State Desynchronization
--------------------------

- [ ] **Pairwise sessions**
  - [ ] There is a defined path from “suspicious session” to “full reset” via a new handshake.
  - [ ] No attempt is made to guess or roll back ratchet state after severe desync.
- [ ] **Group sessions**
  - [ ] Group state summaries (hash, epoch, members) are compared between peers.
  - [ ] Inconsistent summaries cause resync or rebuild, not silent continuation.
- [ ] **Epoch history**
  - [ ] `EpochManager` correctly records and verifies epoch hashes.
  - [ ] Epoch numbers never decrease during normal operation.

7. Sealed Sender Metadata Exposure
----------------------------------

- [ ] **Sealed sender**
  - [ ] Outer envelope contains only recipient_locator, ttl, sp, pad; no sender_id/session_id in clear.
  - [ ] Relay routing uses only recipient_locator; no plaintext sender required for delivery.
  - [ ] Inner package (sender_id, session_id, header, ciphertext) recovered only by recipient.

8. Network Hardening Correctness
--------------------------------

- [ ] **Network hardening**
  - [ ] Mix delays and cover/dummy traffic do not alter payload content.
  - [ ] Undecryptable envelopes (dummy/cover) are dropped without updating replay cache or fork state.
  - [ ] Delayed delivery (deliver_due) does not corrupt envelope content; routing remains payload-blind.

9. Relay Zero-Trust Review
--------------------------

- [ ] **Relay behavior**
  - [ ] Server never attempts to decrypt sealed envelopes; no decryption routines on server.
  - [ ] Only minimal metadata (mailbox/recipient IDs, ttl) used for routing and delivery.
  - [ ] Messages reside only in RAM; no persistent message queues.
- [ ] **Logging (relay and client)**
  - [ ] Logs do not contain plaintext user messages or long-lived secret material.
  - [ ] Sensitive identifiers are minimized or properly redacted.

10. Group Epoch / Membership Transition Review
----------------------------------------------

- [ ] **Group epoch**
  - [ ] Epoch starts at INITIAL_EPOCH (1); never decreases.
  - [ ] Add/remove member increments epoch and rederives GK, AK, group_hash.
- [ ] **Membership**
  - [ ] New members cannot decrypt prior epochs (epoch check + state only for join epoch).
  - [ ] Removed members cannot decrypt future epochs (leaf overwrite, no new state).
  - [ ] Stale or divergent group state is not accepted silently (epoch/hash verification).

11. OPK and Epoch Reuse
-----------------------

- [ ] **OPK reuse**
  - [ ] Code paths guarantee that an OPK is not used for more than one handshake.
  - [ ] Any OPK that appears to be used twice is treated as a serious error.
- [ ] **Group epoch reuse**
  - [ ] There is no code path that resets `epoch` to an earlier value.
  - [ ] Group epoch transitions always derive new secrets via HKDF.

12. Denial-of-Service Surfaces
------------------------------

- [ ] **Network**
  - [ ] There are limits on envelope size and mailbox capacity.
  - [ ] TTLs are enforced; stale envelopes are dropped.
- [ ] **Protocol**
  - [ ] Excessive handshake attempts from a single origin can be rate-limited.
  - [ ] Skipped-key cache exhaustion surfaces as a controlled failure.
- [ ] **Groups**
  - [ ] Abusive add/remove operations (e.g., flapping membership) can be rate-limited or require explicit user approval.

13. Storage Compromise Impact
-----------------------------

- [ ] **Confidentiality**
  - [ ] Database encryption key is distinct from identity/session keys.
  - [ ] Compromised DB reveals message metadata and state, but past plaintexts remain protected by FS/PCS unless keys are also compromised.
- [ ] **Integrity**
  - [ ] Tampered serialized state is detected via signatures, hashes, or epochs.
  - [ ] There is a defined recovery procedure (wipe + re-bootstrap) when tampering is suspected.

14. Logging Review
------------------

- [ ] **Logging**
  - [ ] No plaintext or long-lived key material in logs.
  - [ ] Errors and transitions logged without sensitive payloads; identifiers redacted where appropriate.

15. Memory Lifetime and Secret Handling
----------------------------------------

- [ ] **Key material in memory**
  - [ ] Long-lived keys (identity, group secrets) are minimized in scope where possible.
  - [ ] Ephemeral keys (DH, MK) are freed or overwritten when no longer used.
- [ ] **Temporary buffers**
  - [ ] Temporary byte arrays used for crypto operations are short-lived.
  - [ ] There are no unnecessary copies of sensitive data.

16. Secure Deletion / RAM-Only Caveats
--------------------------------------

- [ ] **Secure deletion**
  - [ ] Wipe API removes local cryptographic material; no guarantee on commodity OS/filesystem that overwrite is complete.
  - [ ] RAM: keys and plaintexts exist in process memory; no guarantee of zeroing after use unless explicitly implemented.
- [ ] **RAM-only**
  - [ ] Relay mailbox is RAM-only; restart loses undelivered messages; no persistent queue.

17. Review Process Notes
------------------------

- [ ] **Unit tests**
  - [ ] Tests cover: identity/pre-keys, X3DH, double ratchet, group membership, replay, fork detection, sealed sender, mailbox TTL, end-to-end flows, and network hardening.
- [ ] **Documentation**
  - [ ] Threat model, invariants, protocol flows, attack surface, and failure modes are documented and kept in sync with code.
- [ ] **Third-party dependencies**
  - [ ] Crypto libraries are up to date and widely used (e.g., libsodium via PyNaCl, `cryptography`).
  - [ ] No home-grown primitives.

This checklist should be used alongside code reviews and tests to evaluate whether the implementation and deployment meet the intended security goals and to identify areas for future hardening.

