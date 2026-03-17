Protocol Flow
=============

This document summarizes the main protocol flows in GhostChat from a message-lifecycle point of view. It is designed for presentations and technical interviews.

1. Identity and Pre-Key Setup
-----------------------------

**Goal:** Provision long-term identity and pre-key material.

```text
Client
  1. Generate Ed25519 identity keypair (IK).
  2. Generate X25519 signed pre-key (SPK).
  3. Sign SPK public key with IK.
  4. Generate batch of X25519 one-time pre-keys (OPKs).
  5. Serialize and publish:
       - identity public key
       - SPK public key + signature
       - OPK public keys
```

Security properties:

- Peers can authenticate SPK against IK.
- OPKs provide one-time forward-secret contributions for future handshakes.

2. Pairwise Handshake (Hybrid X3DH)
-----------------------------------

**Goal:** Establish a shared root key between two clients.

Participants:

- Initiator `I`
- Responder `R` (with published pre-key bundle)

```text
I (client)                                      R (client)
-----------------                               --------------------
Fetch pre-key bundle for R
  - IK_R, SPK_R, {OPK_R_i}

Generate:
  - Ephemeral X25519 keypair E_I

Classical part:
  - DH1 = DH(E_I, SPK_R)
  - DH2 = DH(E_I, OPK_R_j)    (if OPK available)
  - classical_secret = concat(DH1, DH2?)

PQ part (optional backend):
  - R generates PQ keypair (PK_R_pq, SK_R_pq)  [abstracted]
  - I encapsulates to PK_R_pq -> (CT_pq, shared_pq)
  - R decapsulates CT_pq -> shared_pq'

Root derivation:
  - I and R compute:
      root_key = HKDF(classical_secret [+ shared_pq])
```

Result:

- Both sides obtain the same `root_key`, which seeds the double ratchet.

3. Double Ratchet Messaging and Protocol Envelopes
--------------------------------------------------

**Goal:** Achieve forward secrecy and post-compromise security for a session.

Per-session state includes:

- `RK` (root key), `CK_s` (sending), `CK_r` (receiving).
- `DHS` / `DHR` ratchet keys.
- Message counters and skipped-key cache.

Send flow (simplified):

```text
1. If CK_s is None and DHR known:
     - Perform DH ratchet step:
         RK', CK_s = KDF_RK(RK, DH(DHS, DHR))
         RK = RK'
2. Derive message key:
     CK_s', MK = KDF_CK(CK_s)
     CK_s = CK_s'
3. Construct header:
     H = (DH_pub = DHS.pub, pn = PN, n = Ns)
4. AEAD-encrypt plaintext with MK and header as AD.
5. Increment Ns.
```

Receive flow (simplified):

```text
1. Check skipped-key cache for (DH_pub, n); if present, use MK to decrypt.
2. If header.DH_pub != current DHR:
     - Skip remaining keys for old receiving chain.
     - Perform DH receive ratchet:
         RK', CK_r = KDF_RK(RK, DH(DHS, new_DHR))
         RK = RK'; DHR = new_DHR; Ns, Nr reset; DHS refreshed.
3. If n < Nr: treat as duplicate and reject.
4. Skip keys up to n-1, caching them as skipped.
5. Derive MK for n via KDF_CK(CK_r); increment Nr.
6. Decrypt with MK and header as AD.
```

After encryption, the resulting ciphertext and header are wrapped in a
**protocol envelope** containing:

- protocol version
- session_id
- sender_ratchet_key
- message_number
- previous_chain_length
- ciphertext

Replay protection and fork detection are applied against these envelope
fields before the ratchet layer attempts decryption.

4. Group Messaging Flow (MLS-Inspired)
--------------------------------------

**Goal:** Support small-group messaging with epoch-based keys.

States:

- `GE` – group epoch.
- `GK` – epoch secret.
- `AK` – application key.

Group initialization (epoch starts at 1 in implementation):

```text
1. Select group_id.
2. For each member, generate a per-leaf secret.
3. Build a binary tree:
     - Leaf secrets -> leaf node secrets via HKDF.
     - Internal nodes -> HKDF(left || right).
     - Root -> root_secret.
4. Set epoch = INITIAL_EPOCH (1).
5. Derive:
     GK = derive_epoch_secret(root_secret, epoch)
     AK = HKDF(GK, "app-key")
     group_hash = derive_group_hash(group_id, epoch, members, root_secret)
```

Group message send:

```text
1. Sender holds:
     - current GroupState (GE, AK, members, group_hash).
     - local group message counter c.
2. Construct header:
     H = (group_id, epoch = GE, sender_leaf_index, counter = c)
3. AEAD-encrypt plaintext with AK, header + optional AD as associated data.
4. Increment c.
5. Send sealed-sender envelope with H + ciphertext. For relay routing, the group message is wrapped in an envelope with `recipient_locator` (e.g. b64 group_id) and `group_message` payload (`GroupMessage.to_dict()`); clients use `send_group_text` / `recv_group_text` and GroupManager for state.
```

Group message receive:

```text
1. Verify:
     - header.group_id matches local group_id.
     - header.epoch == local GE.  [stale epoch -> reject with EpochMismatchError]
     - sender_leaf_index corresponds to a known member.
2. Replay protection:
     - Check (sender_leaf_index, counter) against replay cache; reject duplicate.
3. Decrypt:
     - Use AK, header + optional AD as associated data.
```

Stale / replayed group message rejection:

- **Stale epoch:** Message with `header.epoch != state.epoch` is rejected (new members cannot decrypt prior epochs; removed members cannot decrypt future epochs).
- **Replayed:** Duplicate `(sender_leaf_index, counter)` in same epoch is rejected by group replay cache.
- **Consistency:** Group hash and epoch checks prevent silent acceptance of divergent state; `verify_consistency` used when comparing state across members.

5. Membership Changes and Epoch Rotation
----------------------------------------

Add member:

```text
1. Append new leaf with fresh secret to tree.
2. Recompute affected path up to root.
3. Increment GE.
4. Derive new GK, AK, and group_hash.
5. Distribute new GroupState to all members (excluding removed parties).
```

Remove member:

```text
1. Overwrite removed member's leaf with fresh secret.
2. Recompute path up to root.
3. Increment GE.
4. Derive new GK, AK, and group_hash.
5. Distribute updated GroupState to remaining members.
```

6. Sealed Sender and Relay Routing
----------------------------------

**Goal:** Deliver messages through an untrusted relay without exposing plaintext or sender identity in clear metadata. This is metadata minimization, not perfect anonymity.

**Outer envelope (what the relay sees):**

- `v` – protocol version
- `recipient_locator` – mailbox key used for routing (e.g. recipient profile id)
- `ttl` – time-to-live
- `sp` – opaque sealed payload (base64); relay does not decrypt or parse it
- `pad` – optional padding

The relay routes using **only** `recipient_locator`. It never sees sender identity, session_id, or ratchet metadata in plaintext.

**Inner protected package (recovered only by the recipient):**

- sender_id, session_id
- ratchet header (dh_pub, pn, n)
- ciphertext (double-ratchet payload)

The inner package is serialized and AEAD-encrypted with a key derived from the session root key (`K_seal = HKDF(root_key, "ghostchat-sealed-sender-v1")`). Only the recipient with the same session can derive K_seal and unseal.

**Sender flow (sealed):**

```text
1. Resolve recipient/session; double-ratchet encrypt plaintext.
2. Build inner sender package (sender_id, session_id, header, ciphertext).
3. Derive sealing key from session root key; seal(inner) -> sealed_payload.
4. Build outer envelope: recipient_locator, ttl, sp = sealed_payload.
5. Submit outer envelope to relay.
```

**Recipient flow (sealed):**

```text
1. Receive outer envelope from relay.
2. Parse outer; try unseal(sp) with each session's sealing key until one succeeds.
3. Recover inner (sender_id, session_id, header, ciphertext).
4. Run replay protection and fork detection on recovered header.
5. Double-ratchet decrypt ciphertext; return plaintext.
```

Replay and fork checks run **after** unseal, using the same logic as the non-sealed path (synthetic protocol envelope from inner fields).

Relay-side:

```text
1. Accept envelope over TLS.
2. Route using get_routing_recipient(envelope) -> recipient_locator only.
3. Optionally apply mix-style delay: schedule with MixRouter, then deliver_due(now) into mailbox.
4. Store full outer envelope in recipient's RAM-only mailbox.
5. Drop on ttl expiry or after delivery. Do not log sender identity.
```

Dummy and cover traffic use the same outer shape; the relay does not distinguish them. The recipient drops undecryptable envelopes (dummies/cover) without updating session state.

6a. Mix-Delay / Cover / Dummy Interaction Points
------------------------------------------------

**Where hardening touches the flow (current implementation):**

1. **Send path (client):**
   - Before submit: optional jitter/batching (timing_defense); optional `get_pending_cover_packets()` and inject cover envelopes; optional dummy envelopes with same outer shape.
   - Envelopes (real, cover, dummy) are submitted to relay; relay does not distinguish.

2. **Relay:**
   - On enqueue: if `use_mix` (or equivalent), `schedule_envelope(envelope, deliver_at = now + delay)`; otherwise enqueue immediately.
   - On delivery: `deliver_due(now)` moves envelopes with `deliver_at <= now` from schedule into recipient mailboxes.
   - Routing uses only `recipient_locator`; no decryption.

3. **Receive path (client):**
   - After fetch: try unseal/decrypt per session. If `drop_undecryptable=True`, envelopes that fail all sessions (dummies, cover, or misrouted) are dropped without updating replay cache or fork state.
   - Only successfully decrypted envelopes update session/replay/fork state.

**Security property:** Delayed/dummy/cover traffic must not corrupt real session state; replay and fork checks apply only to successfully decrypted inner payloads.

7. Message Lifecycle Summary
----------------------------

End-to-end lifecycle of a typical pairwise message:

```text
Client A:
  (1) Ensure session established (X3DH + DR init).
  (2) Double-ratchet encrypt message -> ciphertext + header.
  (3) Seal inner payload -> sealed envelope.
  (4) Apply optional network hardening.
  (5) Send envelope to relay.

Relay:
  (6) Queue envelope with randomized delay and batching.
  (7) Deliver to Client B's mailbox or drop on expiry.

Client B:
  (8) Fetch envelope from mailbox.
  (9) Unseal inner payload.
 (10) Double-ratchet decrypt using header and session state.
 (11) Surface plaintext message to the user.
```

The group lifecycle is analogous but uses the group epoch and application key instead of per-session ratchets for the payload encryption step.

