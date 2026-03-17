# Interview Walkthrough

This document is a guide to explaining GhostChat in a technical interview. It is structured as answers to the kinds of questions an interviewer might ask about the problem, architecture, design tradeoffs, and limitations.

---

## What problem does GhostChat solve?

GhostChat tackles a **narrow but realistic problem**: providing end-to-end encrypted messaging for very small, trusted groups (roughly 3–6 users) over an **untrusted relay**, while demonstrating modern security properties like forward secrecy, post-compromise security, replay protection, and metadata minimization.

The goal is **not** to compete with production messengers, but to:

- Show understanding of how systems like Signal are structured.
- Implement a full stack from identity and key agreement up through group messaging and an untrusted relay.
- Make the system **auditable**: there is a clear threat model, explicit invariants, an attack surface analysis, and a failure mode analysis.
- Provide a codebase you can walk an interviewer through in 10–20 minutes without hand‑waving.

---

## Key architecture decisions

### 1. Untrusted relay and sealed sender

The relay is assumed to be **zero trust**: it can drop, modify, and replay traffic. It should not need to see plaintext or sender identity to route messages. That drove the decision to use a **sealed-sender-style envelope**:

- The **outer envelope** contains only routing data: recipient locator, TTL, opaque sealed payload, and optional padding.
- The **inner payload** contains sender identity, session id, ratchet header, and ciphertext, encrypted with a key derived from the session root key.

This lets the relay function purely as a router and queue, not as a participant in encryption or authentication.

### 2. Identity + prekey model

Each user has an **Ed25519 identity keypair** that acts as their long-term identity. To support asynchronous session setup, GhostChat follows the **Signal-style prekey model**:

- A **signed prekey (SPK)** is an X25519 key signed by the identity key.
- A batch of **one-time prekeys (OPKs)** provide one-time contributions to the handshake.

This is a deliberate choice because it:

- Cleanly separates long-term identity from medium-lived SPKs and short-lived OPKs.
- Makes identity binding explicit and testable: the SPK must verify under the identity key before use.

### 3. X3DH-style handshake with a PQ hook

For pairwise sessions, GhostChat uses an **X3DH-style handshake**:

- Classical X25519 DH over identity/SPK/OPK material.
- A **pluggable interface** for a post-quantum KEM, so the handshake can be extended to be hybrid classical+PQ later.

Both sides assert that their classical and (when enabled) PQ secrets match before deriving the root key via HKDF. This structuring choice reflects an understanding of where PQ support belongs in a modern messenger and reduces the risk of silent downgrades.

### 4. Double ratchet for ongoing messaging

Once a root key is established, GhostChat uses a **double ratchet**:

- Root key, sending and receiving chain keys, ratchet DH keys, message counters, and a bounded skipped-key cache.

The decision to implement a full double ratchet rather than, say, just a simple “session key per message” is important: it demonstrates understanding of **forward secrecy** and **post-compromise security**, and it forces you to think about replay, ordering, and state management.

### 5. MLS-inspired group protocol

Group messaging uses an **MLS-inspired** but simplified protocol:

- Small, fixed-capacity binary tree of node secrets.
- Per-epoch group secret and application key derived from the tree root.
- Epoch number starting at 1 and increasing on all membership changes.
- Group hash that commits to group_id, epoch, membership, and tree root.

This gives clean properties around membership changes: new members cannot decrypt older epochs; removed members cannot decrypt newer epochs.

---

## Why is the protocol structured this way?

From an interviewer’s perspective, you want to be able to justify **why** the protocol is structured the way it is, not just describe it.

1. **Identity + prekeys** are used to decouple long-term identity from handshake material, enabling asynchronous setup and limiting the blast radius of key leakage.
2. The **X3DH-style handshake** is a natural fit for modern messengers: it provides authentication and key agreement even when one party is offline, and it integrates well with prekeys.
3. The **double ratchet** sits on top of the handshake because you need a shared root key first; then you want per-message keys that evolve over time, which is exactly what the ratchet gives.
4. The **sealed sender** layer wraps double ratchet messages into an envelope that minimizes what the relay learns. Structurally, it belongs above the ratchet (which knows nothing about routing) and below the transport.
5. The **group epoch model** mirrors the idea in MLS that membership changes should cause epoch changes and key rotation. This keeps group security manageable and reasoned about in terms of epochs rather than individual messages.
6. The **network hardening layer** is intentionally orthogonal: it operates on opaque envelopes and timing only, ensuring it can’t break cryptographic assumptions.

In short: each layer has a clearly defined concern, which simplifies reasoning, testing, and future changes.

---

## Tradeoffs made in the prototype

GhostChat deliberately makes several tradeoffs in favor of clarity and scope:

1. **Simplicity over completeness**
   - The group protocol is MLS-inspired but not spec-compliant.
   - The WebSocket server is a skeleton; tests use an in-memory transport instead of a full wire protocol.
   - There is no complex user identity directory; prekey distribution is assumed to be handled externally.

2. **Readability over optimization**
   - Code paths are structured for clarity: explicit dataclasses, named fields, separate modules for invariants and attack surfaces.
   - There is no attempt to optimize for performance or huge group sizes.

3. **Best-effort metadata protection**
   - Mix delay, cover traffic, and dummy packets are implemented, but not tuned to any specific anonymity guarantees.
   - The design explicitly states that it does not provide strong anonymity against a global passive adversary.

4. **Test-driven instead of UI-driven**
   - The primary interface is pytest-based, not a CLI or GUI.
   - This is a tradeoff toward verifiability and away from user-facing polish.

These tradeoffs make the project smaller and more explainable while still being technically interesting.

---

## Security challenges encountered

Some good talking points around challenges:

1. **Replay and fork handling**
   - Implementing replay protection and fork detection on top of the double ratchet required careful thought about what constitutes “the same message” and how to detect regressions in ratchet state.
   - The solution was a combination of:
     - A replay cache keyed by (session_id, sender_ratchet_key, message_number).
     - A fork-detection state that tracks monotonicity of message number and previous_chain_length.
     - A `SessionResetState` that records when a session should be torn down and re-handshaken instead of trying to “recover” in place.

2. **Group state consistency**
   - Ensuring that group members agree on epoch, membership, and keys is non-trivial.
   - GhostChat uses a group hash that commits to the full state and a set of verification helpers so clients can detect divergent or stale state and trigger resync.

3. **Ensuring hardening doesn’t break correctness**
   - It’s easy to accidentally let dummy or cover traffic interact with replay/fork state or counters in a way that breaks real sessions.
   - The implementation carefully drops **undecryptable** sealed envelopes without touching session state, and tests specifically cover mixed real + dummy + cover scenarios.

4. **Documenting limitations honestly**
   - A subtle challenge was to clearly document where the system stops. For example: prekey distribution is not authenticated; PQ is a placeholder; secure deletion is best-effort.
   - This is important both from an engineering ethics perspective and because interviewers will often probe for what you decided **not** to implement.

---

## What would be improved in a production system?

In an interview, it’s useful to show you know how to move from prototype to production. Some natural next steps:

1. **Authenticate prekey distribution**
   - Introduce a signed directory service, TOFU/pinning, or out-of-band verification for identity and prekeys.
   - Add revocation and rotation flows for identity and SPKs.

2. **Real post-quantum support**
   - Integrate a real KEM such as Kyber/ML-KEM into the handshake, with careful versioning and downgrade protection.
   - Analyze hybrid key derivation and its impact on forward secrecy and PCS.

3. **Stronger anonymity and traffic shaping**
   - Move from “mix delay + cover” to a more principled mixnet design with multi-hop routing and more consistent padding and timing behavior.
   - Evaluate anonymity properties under different adversary models.

4. **Operational hardening**
   - Add rate limiting on handshake and relay operations to mitigate DoS.
   - Harden logging to avoid leaking sensitive identifiers or metadata.
   - Integrate encrypted storage into all critical code paths and handle key lifecycle more rigorously.

5. **Formal verification and audits**
   - Apply tools like Tamarin or ProVerif to verify key protocol flows (e.g., that forward secrecy holds under certain compromise models).
   - Engage external reviewers to audit the design and code.

Discussing these steps shows that you understand the gap between a research prototype and a production system.

---

## What parts of the project were the hardest?

You can tailor this section to your own experience, but good answers include:

1. **Designing the invariants and tests**
   - Defining the security invariants up front (e.g., “removed members must not decrypt future epochs”, “replayed one-to-one messages must be rejected before decryption”) and then mapping them to concrete code and tests was non-trivial.
   - This required reading across multiple layers (ratchet, protocol, group) and ensuring they lined up.

2. **Keeping the relay truly payload-blind**
   - It’s easy to accidentally leak information in routing logic or logs.
   - The code had to be structured so that the relay never needed to inspect sender identity or inner payload fields, and tests like “relay remains sender-blind” help enforce that.

3. **Balancing simplicity with realism**
   - Implementing the full Signal protocol is out of scope; implementing something too toy-like would not be interesting.
   - Striking a balance with an MLS-inspired group model, sealed sender, and a real double ratchet while still being explainable was a design challenge.

4. **Writing honest documentation**
   - Documenting attack surfaces and failure modes in a technically honest way forces you to confront edge cases and limitations. This is time-consuming but valuable and is often missing from student projects.

Mentioning these “hard parts” shows depth: that you’ve thought about more than just getting code to run.

---

## How to use this document in an interview

- Use the **problem and architecture sections** to answer “What is this project?” and “How does it work?”.
- Use the **tradeoffs and challenges sections** to answer “What was hard?” and “What did you learn?”.
- Use the **production improvements section** to answer “How would you take this to production?”.
- Keep references to specific modules and docs handy (`docs/PROTOCOL_FLOW.md`, `docs/SECURITY_INVARIANTS.md`, `docs/ATTACK_SURFACE_ANALYSIS.md`) so you can point to concrete code if the interviewer wants to dive deeper.

The overall story you want to tell is: *“I implemented a miniature but realistic secure messaging stack, understood the underlying protocols, and documented its properties and limitations clearly.”*

