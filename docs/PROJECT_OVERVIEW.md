# Project Overview

GhostChat is a small, research-grade prototype of a secure messaging system for **very small, trusted groups**. It is designed to be read, tested, and explained, not to be deployed as a production messenger. This document gives a narrative overview of the full system: what problems it targets, how it is structured, and what security properties it aims to provide.

---

## 1. Motivation

Modern secure messengers like Signal have converged on a common pattern: long-term identity keys, asynchronous prekeys, a key-agreement handshake, and a double ratchet for forward secrecy and post-compromise security. However, these systems are complex and difficult to study in isolation. GhostChat’s goal is to provide a **compact, auditable implementation** of this architecture, with:

- Explicitly documented **security invariants**.
- A clearly defined **threat model** and attack surface.
- Tests that drive and verify the implementation.
- Honest documentation about what is and is not protected.

The focus is on **small groups** (3–6 users) and an **untrusted relay**. The relay should never need plaintext or sender identity to route traffic, and membership changes in groups should be cryptographically enforced, not just reflected in UI.

---

## 2. Threat model (high level)

GhostChat assumes:

- An attacker can **observe and modify network traffic**, including replaying and reordering messages.
- The relay server may be **malicious or compromised**; it should not be trusted with plaintext or sender identity.
- Devices may be **lost or stolen**, exposing local databases.

GhostChat **does not** attempt to defend against:

- Full **device/OS compromise** (e.g. malware, keyloggers).
- A global passive adversary capable of perfect **traffic analysis** and correlation.
- Compromise of the local storage encryption key (if used) or arbitrary compromise of cryptographic libraries.

Within this scope, the goal is to:

- Protect message **confidentiality and integrity** end-to-end.
- Provide **forward secrecy** and **post-compromise security**.
- Enforce **group membership and epochs** cryptographically.
- Minimize what the relay learns about who is talking to whom.

Detailed threat modeling for Phase 1 (identity and prekeys) lives in `docs/THREAT_MODEL.md`; later documents (invariants, attack surface, failure modes) extend it to the full protocol.

---

## 3. Identity and key management

Each user has a long-term **Ed25519 identity keypair**. The public identity key is the stable identifier; the system does not depend on phone numbers or email addresses.

To support asynchronous session setup, GhostChat uses:

- A **signed prekey (SPK)**: an X25519 key signed by the identity key.
- A batch of **one-time prekeys (OPKs)**: X25519 keypairs used once each.

The **prekey bundle** (identity public key, SPK + signature, OPKs) is published via whatever directory or API the application uses. GhostChat itself does not implement a directory; it assumes the application can deliver these bundles to peers.

Key properties:

- SPK signatures are verified under the identity key before trust is established.
- OPKs are consumed at most once; attempting to reuse an OPK raises an error.
- Serialization is explicit and versioned; there is no use of unsafe generic serializers.

This layer establishes the **binding** between identity and prekeys and provides the raw material for the handshake.

---

## 4. Secure session establishment

Pairwise sessions are established via a **hybrid X3DH-style handshake**:

- The classical part uses X25519 DH between the initiator’s ephemeral key and the responder’s SPK and OPK.
- The PQ part is a pluggable interface (placeholder in this prototype), intended to support a post-quantum KEM later.
- The handshake asserts that both sides derive the same classical (and, when configured, PQ) contributions.
- A shared **root key** is then derived via HKDF across these contributions.

This root key seeds a per-session **double ratchet**:

- Each session has a root key, sending and receiving chain keys, and DH ratchet keypairs.
- The ratchet advances on new DH operations and per-message chain key evolution.
- Old message keys are discarded; skipped keys are stored in a bounded cache for out-of-order delivery.

In tests, a helper method can create a “symmetric” session directly from a root key and DH parameters to focus on ratchet behavior without implementing a full client UI.

---

## 5. Encrypted messaging pipeline

The one-to-one messaging pipeline runs as follows:

1. **Application → message API**
   - A client calls `send_text(profile, recipient_profile, peer_id, text, sealed_sender=...)`.
   - The message API looks up the `SessionManager` for the sender.
2. **Double ratchet encryption**
   - `SessionManager.encrypt_for` (or `encrypt_sealed`) runs the double ratchet:
     - Perform a DH ratchet step if required.
     - Derive a new message key from the sending chain key.
     - Produce an AEAD ciphertext with the ratchet header as associated data.
3. **Protocol envelope**
   - For non-sealed messages, the ciphertext and header are wrapped in a `ProtocolEnvelope` with:
     - Version, session_id, sender_ratchet_key, message_number, previous_chain_length, ciphertext, optional meta.
4. **Transport**
   - In tests, the message is delivered via an in-memory endpoint; in a full system it would go through the relay.
5. **Receiving**
   - The recipient’s `SessionManager` applies:
     - **Replay protection** using a per-session replay cache.
     - **Fork detection** on regressions in message number or previous chain length.
     - **Session reset** markers if replay or fork is detected.
   - If checks pass, the double ratchet decrypts the ciphertext and returns plaintext to the application.

This pipeline is **stateful**: each message both uses and updates session state. The replay/fork/reset logic is designed to detect inconsistencies before decryption and force a clean re-handshake instead of silently continuing in a bad state.

---

## 6. Protocol validation layer

Above the ratchet, the **protocol layer** enforces structural and state invariants:

- **Envelope parsing:** `ProtocolEnvelope.from_dict` and `SealedOuterEnvelope.from_dict` validate:
  - Version numbers.
  - Required fields (session_id, ratchet key, counters, ciphertext).
  - Base64 encoding and integer conversions.
- **Replay protection:** `SessionReplayCache` rejects duplicate (session_id, ratchet_key, message_number) triples and stale message numbers.
- **Fork detection:** A fork-detection state tracks monotonicity of message number and previous chain length; any regression marks the session as needing reset.
- **Session reset:** `SessionResetState` records when a session should be torn down and re-established.

For groups, a similar validation layer ensures:

- Epochs do not go backwards.
- Membership and group hash are consistent.
- Group messages carry valid (group_id, epoch, sender_leaf_index, counter).
- Replay is prevented via a per-sender (leaf_index, counter) cache.

Overall, this layer is about **failing closed**: malformed or inconsistent inputs are rejected early and explicitly.

---

## 7. Metadata protection strategy

GhostChat’s metadata strategy has two parts:

1. **Sealed sender**
   - The **outer** envelope contains only what the relay needs to route:
     - `recipient_locator`, `ttl`, sealed payload (`sp`), and optional `pad`.
   - The **inner** payload contains sender identity, session id, ratchet header, and ciphertext, encrypted with a key derived from the session root.
   - The relay never needs to see sender identity or ratchet metadata in plaintext.
2. **Network hardening**
   - Optional **mix-style delay**: envelopes can be scheduled by `MixRouter` and delivered later via `deliver_due(now)`.
   - **Dummy packets**: sealed-sender-like envelopes with no real payload, indistinguishable at the relay.
   - **Cover traffic**: periodic sealed envelopes sent even when the user is idle.

These measures reduce what the relay learns but do **not** hide:

- Which mailbox is targeted (recipient locator).
- Coarse traffic volume and timing.

GhostChat explicitly documents that this is **metadata minimization**, not strong anonymity.

---

## 8. Group messaging design

GhostChat’s group layer is **MLS-inspired but simplified** for small, trusted groups:

- Groups have:
  - `group_id` (opaque).
  - `epoch` (starting at 1 and incrementing on membership changes).
  - A mapping from identity public key to leaf index.
  - A fixed-size binary tree of node secrets.
  - An epoch secret (**group_secret**), application key, and group hash.
- The **key schedule**:
  - Derives per-leaf node secrets from random leaf secrets.
  - Derives internal node secrets upward to a root secret.
  - Derives an epoch secret and application key from the root and group metadata.
  - Derives a group hash committing to group_id, epoch, membership, and root.
- **Membership changes**:
  - `add_member` inserts a new leaf, recomputes the tree, increments the epoch, and derives new secrets.
  - `remove_member` overwrites a leaf with fresh randomness, recomputes the tree, increments the epoch, and derives new secrets.
  - Only current members receive the new state for the new epoch.

Group messages carry (group_id, epoch, sender_leaf_index, counter) and are encrypted with the application key for that epoch. Recipients:

- Reject stale epochs (e.g., prior to their join epoch or after they have been removed).
- Reject replayed (sender_leaf_index, counter) pairs.
- Verify membership and group_id before decryption.

This design enforces:

- New members cannot decrypt past epochs.
- Removed members cannot decrypt future epochs.
- Stale or divergent group state is not accepted silently.

---

## 9. Relay architecture

The **relay** is a RAM-only, payload-blind router:

- Uses `server/router.Router` to:
  - Compute the routing key via `get_routing_recipient(envelope)` (recipient locator only).
  - Enqueue envelopes into per-recipient mailboxes.
  - Optionally use a `MixRouter` for scheduled (delayed) delivery.
- Uses `server/memory_mailbox.MemoryMailboxStore` and `server/ttl` helpers to:
  - Store envelopes in memory only.
  - Drop envelopes when their TTL expires or after a restart.

The relay:

- Never decrypts payloads (no decryption keys are present).
- Never needs to read sender identity when sealed sender is used.
- Is explicitly allowed to lose undelivered messages (prototype design).

A minimal FastAPI app (`server/websocket_server.py`) exists as a skeleton entrypoint (health endpoint only), giving a natural place to attach a real WebSocket relay in future work.

---

## 10. Storage model

GhostChat includes an **encrypted storage abstraction** (e.g., an encrypted SQLite database) for:

- Identity keys.
- Session state (ratchets, replay/fork state).
- Group state (epochs, application keys, membership).
- Optional message history.

In the current prototype:

- The storage layer is designed but not deeply integrated into the test demos.
- All long-term storage is assumed to be encrypted; plaintext session keys are not intended to be written directly to disk.
- An “emergency wipe” operation is planned to remove local secrets, but **secure deletion** (e.g., overwriting, SSD details) is not guaranteed and is documented as such.

The recommended mental model is: storage is **defense in depth**, not a replacement for endpoint security.

---

## 11. Security properties achieved

Given its assumptions, GhostChat aims to provide:

- **Confidentiality and integrity** of one-to-one and group messages between honest endpoints.
- **Forward secrecy**, once ratchets advance beyond messages and OPKs are consumed.
- **Post-compromise security**, after new DH ratchet steps and group epoch rotations following compromise.
- **Replay protection** and **fork detection** for one-to-one sessions, with explicit reset rather than silent continuation.
- **Group membership enforcement** via epoch rotation and key derivation:
  - New members do not gain access to prior epochs.
  - Removed members lose access to future epochs.
- **Metadata minimization** at the relay:
  - No plaintext sender identity or ratchet metadata in sealed sender mode.
  - Optional mix delay, cover, and dummy traffic make trivial traffic analysis harder.

These properties are backed by:

- Unit and integration tests.
- A documented set of invariants and attack surfaces (`docs/SECURITY_INVARIANTS.md`, `docs/ATTACK_SURFACE_ANALYSIS.md`, `docs/ATTACK_DEFENSE_MATRIX.md`).

---

## 12. Known limitations

Key limitations to be aware of:

- **No strong anonymity:** Recipient, timing, and coarse size remain visible. The system does not claim anonymity against a global passive adversary.
- **No device/OS compromise protection:** A compromised endpoint can exfiltrate keys and plaintext; GhostChat does not attempt to mitigate this.
- **Unauthenticated key distribution:** Prekey/identity bundles can be substituted by a malicious directory; higher-level mechanisms (TOFU/pinning, signed directories) are future work.
- **Incomplete PQ story:** The handshake is structured to support PQ KEMs, but the current backend is a placeholder; there is no real post-quantum security yet.
- **Prototype relay:** RAM-only mailboxes, no persistent queue, no rate limiting or DoS protection.
- **Storage caveats:** Secure deletion and RAM zeroing are not guaranteed; protection relies on OS and hardware behavior.

These limitations are intentional for a research prototype and are documented in more detail in the threat model, invariants, attack surface, and failure mode documents. They also form the basis of the project’s **future roadmap** toward a production-quality system.

