# Interview Explanation

A technical narrative for explaining GhostChat in a technical interview, project defense, or portfolio walkthrough. Target length: roughly 1200–1800 words.

---

## Project motivation

GhostChat is a research prototype for a secure, end-to-end encrypted messaging system aimed at very small, trusted groups—on the order of three to six users. The goal was not to build a product to compete with Signal or WhatsApp, but to implement and document a **complete security architecture**: from identity and key exchange through pairwise and group messaging, with an untrusted relay and optional metadata hardening. I wanted something that could be explained clearly, tested rigorously, and defended in a final-year or portfolio context—with honest limitations and no overclaiming.

---

## Why this architecture

The design follows the same broad pattern as modern E2E messengers: long-term identity, short-lived prekeys, a key-agreement handshake, then a stateful symmetric layer (double ratchet) for ongoing encryption. The relay is **untrusted**: it should not need to see plaintext or sender identity to route. That drove the choice of sealed-sender-style envelopes and a RAM-only server with no decryption. For groups, I wanted **epoch-based key rotation** so that membership changes are cryptographically enforced—new members cannot read the past, removed members cannot read the future—without implementing full MLS. The result is a layered stack: identity and prekeys, X3DH-style handshake, double ratchet, protocol envelopes with replay and fork handling, sealed sender, network hardening hooks, and an MLS-inspired group layer. Each layer has a clear responsibility and is testable in isolation.

---

## Identity and prekey model

Each client has an **Ed25519 identity keypair** as a long-term identifier. There is no phone number or email in the protocol; the public identity key is the stable handle. To support asynchronous key agreement, we add **prekeys**: a **signed prekey (SPK)**, which is an X25519 key signed by the identity key, and a batch of **one-time prekeys (OPKs)**. The SPK is used in the handshake and must verify under the identity key before we establish trust; that binding is the basis for authenticating the handshake. OPKs are consumed at most once and give an extra forward-secrecy contribution. The prekey bundle is versioned and serialized in a strict format; there is no ad-hoc or unsafe deserialization. The main limitation is that the **distribution channel** for identity and prekeys is not cryptographically authenticated in the prototype—so a malicious directory could substitute keys. In production you’d add authentication (e.g. signed directory, TOFU, or key pinning).

---

## Why the hybrid handshake matters

The handshake is **X3DH-style** with a **pluggable post-quantum (PQ) layer**. The classical part is X25519 Diffie–Hellman: initiator ephemeral with responder’s SPK, and optionally with an OPK. The PQ part is behind an interface so it can be swapped for a real KEM (e.g. Kyber/ML-KEM) later; in the prototype it’s a placeholder. The important part is that the **root key** is derived from both classical and PQ outputs (when PQ is enabled), and the code **asserts** that both sides get the same classical and PQ values before deriving the root key. That prevents subtle mismatches and downgrade bugs. The hybrid design matters for **future-proofing**: once a real PQ KEM is plugged in, you get a single root key that depends on both classical and PQ agreement, so the handshake remains one coherent step.

---

## Why the double ratchet matters

After the handshake, the session uses a **double ratchet**: a root key plus sending and receiving chain keys, with X25519 ratchet keys so that each new DH step refreshes the root and advances chains. That gives **forward secrecy**—old message keys are not kept—and **post-compromise security**: after a new DH step, the attacker who had a snapshot of state can no longer decrypt future traffic. The implementation supports out-of-order delivery within a **bounded skipped-key cache**; if the gap is too large, we raise an error and the session can be reset. So we get FS and PCS without unbounded state, and the ratchet is the single place where per-message keys are derived and used.

---

## Why replay, fork, and reset checks exist

Even with a correct ratchet, **replay** or **forked state** could cause confusion or security issues. So before we ever call the ratchet decrypt, we run **replay protection** (a cache keyed by session_id, sender ratchet key, and message number) and **fork detection** (regression in message number or previous chain length). If we detect replay or fork, we **mark the session for reset** and do not attempt blind decryption. That way, protocol inconsistency surfaces explicitly and the application can tear down the session and re-handshake. The invariant is: **replay and fork are detected before we use the ratchet**, and **session reset is the prescribed recovery**. Without that, we might accept duplicate or inconsistent messages and corrupt application state.

---

## What sealed sender achieves and what it does not

**Sealed sender** means the **outer** envelope the relay sees contains only routing and an opaque blob: recipient locator, TTL, sealed payload, and optional padding. The **inner** package—sender identity, session id, ratchet header, ciphertext—is encrypted with a key derived from the session root so that **only the recipient** can open it. So the relay can route without ever seeing who sent the message; it only sees “deliver this blob to this mailbox.” That gives **metadata minimization** at the relay: no plaintext sender identity, no session or ratchet metadata in the clear. What it **does not** give is strong anonymity: the relay still sees recipient (mailbox), timing, and size. We don’t do padding normalization or constant-time delivery, and we don’t claim to resist a global adversary doing traffic analysis. So sealed sender is a clear improvement over “sender in the clear” but is not an anonymity guarantee.

---

## Why network hardening was added

On top of sealed sender, we added **optional** hardening: **mix-style delays** (randomized delivery time), **cover traffic** (periodic dummy packets), **dummy packets** (same shape as real traffic), and **timing jitter**. The goal is to make simple timing and volume correlation harder, not to provide a mixnet or strong anonymity. The implementation ensures that **delayed, cover, and dummy traffic do not corrupt real session state**: only successfully decrypted envelopes update replay and fork state; undecryptable envelopes are dropped. So we get a first-stage **anonymous network hardening** layer that raises the bar for casual analysis without overclaiming.

---

## How the group epoch model works

Groups use an **MLS-inspired** design: a small binary tree of secrets, one leaf per member, with internal nodes derived by HKDF. The **root secret** for an epoch is used to derive an **epoch secret**, an **application key** for encrypting group messages, and a **group hash** that commits to group_id, epoch, membership, and root. **Epoch starts at 1** and increments on every add or remove. When we **add** a member, we add a new leaf, recompute the tree, increment the epoch, and derive new epoch secret and application key; the new member receives state only for the new epoch, so they **cannot decrypt prior epochs**. When we **remove** a member, we overwrite their leaf with a fresh secret, recompute the tree, and increment the epoch; the removed member is not given the new state, so they **cannot decrypt future epochs**. Each group message carries group_id, epoch, sender leaf index, and counter; receivers check epoch and membership and reject stale or replayed messages. So the group epoch model is the mechanism that enforces join/leave semantics.

---

## Main prototype limitations

I’m explicit about what we don’t guarantee. **No strong anonymity**: timing and size are visible; no formal anonymity analysis. **No protection against full device or OS compromise**: if the machine is owned, keys can be exfiltrated. **PQ is pluggable but not yet real**: the handshake is structured for it, but the backend is a placeholder. **Prekey distribution** is not authenticated; a malicious directory could substitute keys. **Relay is best-effort**: RAM-only mailboxes, so restart loses undelivered messages; no guaranteed delivery. **No rate limiting or DoS hardening** beyond bounded caches and TTLs. **Secure deletion** is best-effort; we don’t guarantee overwrite or RAM zeroing. And we don’t claim to be stronger than Signal or other production systems—we document what is implemented and what is not.

---

## How I would harden it next for production

For a production-grade system I’d focus on: **authenticated prekey distribution** (signed directory or out-of-band verification and pinning); **a real PQ KEM** (e.g. Kyber) in the handshake; **rate limiting and DoS controls** on the relay and on handshake/session reset; **padding and timing normalization** to reduce metadata leakage; **persistent or replicated mailbox** if delivery guarantees are required (with clear trust and privacy tradeoffs); **secure deletion** where possible (key zeroing, careful buffer handling); and **formal or third-party review** of the protocol and critical code paths. The current prototype is a solid base for that kind of hardening because the layers are separated, the invariants are documented, and the tests lock in the intended behavior.

---

## Summary

GhostChat is a research prototype that implements a full secure-messaging stack: identity and prekeys, hybrid X3DH, double ratchet, replay and fork detection with session reset, sealed sender, optional network hardening, and MLS-inspired group messaging with epoch rotation. The architecture is chosen to keep the relay untrusted and to enforce membership and ordering invariants. The documentation and tests make it possible to explain, review, and extend the system without overclaiming—which is what makes it interview-ready and academically defensible as a final-year or portfolio project.
