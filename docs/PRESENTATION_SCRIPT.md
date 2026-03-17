# Presentation Script (5–8 minutes)

This script is written so you can read it alongside slides when presenting GhostChat as a final-year or portfolio project.

---

## 1. Problem: secure messaging challenges

“I want to start by framing the problem GhostChat is trying to explore.

Modern secure messengers like Signal solve a hard problem: they need to provide end-to-end encryption, forward secrecy, and post-compromise security, while running over an untrusted network and often through an untrusted relay. They also have to deal with group messaging and metadata privacy.

The downside is that real production systems are complex and not easy to study or explain. My goal with GhostChat was to build a **small, auditable prototype** that implements the same architectural ideas, but in a way that can be read, tested, and defended in an interview or a project defense.”

---

## 2. Design goal of GhostChat

“The design goals were:

- First, to keep the **relay untrusted**. The relay should never need plaintext or sender identity to route messages.
- Second, to use **modern end-to-end primitives**: identity keys, an X3DH-style handshake, and a double ratchet.
- Third, to support **small-group messaging** with explicit epoch rotation, so joining late doesn’t give you the past and being removed cuts you off from the future.
- And finally, to be **technically honest**: document the threat model, invariants, and limitations, rather than claiming more than the prototype can actually do.”

---

## 3. High-level architecture

“At a high level, GhostChat is layered:

- At the bottom is the **crypto layer**: Ed25519 identity keys, X25519 prekeys, HKDF, and an X3DH-style handshake.
- On top of that is the **ratchet layer**, which is a double ratchet implementation.
- The **protocol layer** adds envelopes, sealed sender, replay protection, fork detection, and session reset.
- The **group layer** provides an MLS-inspired group state, epoch rotation, and group messaging.
- Then we have a **network hardening layer** with mix-style delays, cover traffic, and dummy packets.
- Finally, there’s the **relay server layer**, which is a RAM-only router that sees only opaque encrypted envelopes.

Clients sit on top of this stack, and there’s also a storage abstraction for encrypted local state.”

You can point to `docs/ARCHITECTURE_DIAGRAM.md` here.

---

## 4. Key protocol components

“Let me quickly walk through the key protocol components.

**Identity and prekeys:** Each user has an Ed25519 identity keypair, plus a signed prekey and a batch of one-time prekeys. The signed prekey is verified under the identity key before we trust it, and one-time prekeys are consumed once to give extra forward secrecy.

**Handshake:** Using that material, the handshake is X3DH-style. It’s hybrid in the sense that the code is structured to also mix in a post-quantum KEM later, even though the current backend is a placeholder. Both sides assert that their classical (and PQ) shared secrets match before deriving the root key.

**Double ratchet:** Once we have a root key, we initialize a double ratchet. That gives us forward secrecy and post-compromise security – each message advances the key state, and old keys are discarded.

**Group protocol:** For groups, we maintain a per-group state with an epoch number, a tree of secrets, an epoch secret, an application key, and a group hash. Epochs start at 1 and increase when members are added or removed.”

---

## 5. How a message flows through the system

“Here’s how a typical one-to-one message flows through GhostChat.

On the sender:

1. The application calls into the **message API** with some plaintext.
2. The session manager runs the **double ratchet**, derives a new message key, and encrypts the plaintext with AEAD.
3. The result is wrapped into a **protocol envelope** that includes the ratchet header and ciphertext.
4. For sealed sender, that inner data is wrapped again into a sealed-sender outer envelope, which exposes only a recipient locator and an opaque encrypted blob.

On the relay:

5. The relay uses the recipient locator to route the envelope into a RAM-only mailbox. It never decrypts the payload.
6. Optional mix-style delays, cover traffic, and dummy packets operate purely on the outer envelopes and timing.

On the recipient:

7. The recipient fetches envelopes from the mailbox, unseals the inner payload if necessary, and passes the header into **replay protection and fork detection**.
8. If those checks pass, the double ratchet decrypts the ciphertext and the application gets the plaintext.

So there are two big lines of defense: **encryption at the endpoints**, and **validation before decryption**.”

You can briefly show the one-to-one message path diagram from `docs/ARCHITECTURE_DIAGRAM.md`.

---

## 6. Group messaging approach

“Group messaging is handled by a simplified, MLS-inspired protocol.

- Each group has an ID, an epoch number starting at 1, a tree of node secrets, and a mapping from identity keys to leaf indices.
- The tree is used to derive a root secret, then an epoch secret and a symmetric application key per epoch.
- Every time a member is added or removed, we recompute the tree, increment the epoch, and derive new keys.

Messages carry the group ID, the epoch, the sender’s leaf index, and a counter. Receivers:

- Reject stale epochs.
- Reject unknown senders.
- Reject replayed (sender, counter) pairs.

This gives you two important guarantees:

- New members can’t decrypt **past epochs**.
- Removed members can’t decrypt **future epochs**.”

---

## 7. Metadata protection layer

“On the metadata side, GhostChat uses two ideas:

1. **Sealed sender** – The outer envelope that the relay sees only contains the recipient locator, a TTL, an opaque ciphertext blob, and optional padding. Sender identity, session ID, and ratchet metadata live inside the sealed blob and are encrypted between endpoints.

2. **Network hardening** – We add optional mix-style delay, dummy packets, and cover traffic. Dummy and cover packets use the same outer format as real messages, and the relay can’t tell them apart. The recipient just drops undecryptable envelopes without touching session state.

This doesn’t provide strong anonymity – timing and volume are still visible – but it does raise the bar for simple traffic analysis while keeping the relay payload‑blind and sender‑blind.”

---

## 8. Security guarantees and limitations

“In terms of guarantees, GhostChat aims to provide:

- End-to-end confidentiality and integrity for one-to-one and small-group messages.
- Forward secrecy and post-compromise security via double ratchet and group epoch rotation.
- Replay protection and fork detection for pairwise sessions, with explicit session reset.
- Group membership enforcement based on epochs so that joins and leaves are cryptographically enforced.
- Metadata minimization at the relay, especially in sealed sender mode.

But it is very important to be honest about limitations:

- It is **not** a strong anonymity system; a global adversary can still do traffic analysis.
- It does not defend against **device compromise** – if the endpoint is owned, keys and plaintext can be stolen.
- Prekey distribution is not authenticated in this prototype – a malicious directory could substitute keys.
- The post-quantum layer is a **placeholder interface**; there is no real PQ KEM yet.
- The relay has no rate limiting or DoS protections beyond simple bounds and TTLs.

These limitations are all documented in the threat model, attack surface, and failure mode analyses.”

---

## 9. Demonstration summary

“For a demo, I typically run a set of pytest-based scenarios:

- A basic end-to-end flow where Alice and Bob have a ratcheted session and exchange messages.
- A replay test that shows a duplicated envelope is rejected and the session is marked for reset.
- A sealed sender test where the relay only sees recipient_locator and an opaque blob, and the recipient recovers sender identity from the inner payload.
- Group tests showing epoch rotation when adding Dave and removing Charlie, and verifying that Dave can’t read past epochs and Charlie can’t read future ones.
- A network-hardening test mixing real messages, dummy packets, and cover traffic, where only the real message is decrypted.

All of these tests are in the repository and map directly to the invariants I just described.”

---

## 10. Future improvements

“To turn this into something closer to production, there are several directions:

- **Stronger key distribution** – for example, signed directories or TOFU/pinning for identity and prekeys.
- **Real post-quantum integration** – plugging in a real Kyber/ML-KEM implementation into the handshake.
- **Better anonymity** – moving toward a real mixnet model with larger anonymity sets and stronger padding and timing defenses.
- **Full MLS compliance** – replacing the simplified group protocol with a spec-complete implementation.
- And finally, **formal verification and external review** – using tools like Tamarin or ProVerif to analyze key flows and invariants, and having the code reviewed by cryptography experts.

The current prototype is structured so that those improvements can be added layer by layer without a full redesign.”

You can close with a short sentence like: “Overall, GhostChat is a compact but complete example of modern secure messaging architecture, designed to be read, tested, and explained.”

