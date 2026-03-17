# Server Security Notes

This document describes the relay server’s security posture and what it can and cannot see when handling sealed sender and legacy envelopes.

## Design Principles

- **Zero trust:** The relay does not decrypt message content or sealed payloads.
- **Minimal routing:** Routing uses only the recipient locator; sender identity is not required for delivery when using sealed sender.
- **RAM-only:** Mailbox storage is in memory only; no persistent plaintext message store.
- **No sender-identity logging:** The server must not log or persist sender identity in plaintext.

## What the Relay Can See

- **Recipient locator** – The mailbox key (e.g. profile id or hash) used to route the message. Required for delivery.
- **Outer envelope structure** – Protocol version (`v`), `ttl`, sealed payload (`sp`) as an opaque blob, optional padding (`pad`). The relay does not parse or decrypt `sp`.
- **Timing and volume** – When messages arrive and how many bytes are sent. This is inherent to any relay and is not hidden by sealed sender.

## What the Relay Cannot See (Sealed Sender Path)

- **Sender identity** – Not present in the outer envelope; it is inside the sealed payload, which only the recipient can decrypt.
- **Session identifier** – Same as above; inside the sealed payload.
- **Ratchet metadata** – DH public key, message numbers, previous chain length; all inside the sealed payload.
- **Message plaintext** – Protected by double ratchet inside the sealed payload; the relay never has keys to decrypt.

## Sealed Sender Outer vs Inner

| Location   | Fields |
|-----------|--------|
| **Outer** (relay-visible) | `v`, `recipient_locator`, `ttl`, `sp` (opaque), `pad` |
| **Inner** (recipient-only) | `sender_id`, `session_id`, `dh_pub`, `pn`, `n`, `ciphertext` |

The inner package is AEAD-encrypted with a key derived from the session root key (`K_seal = HKDF(root_key, "ghostchat-sealed-sender-v1")`). Only a client that shares that session with the sender can derive `K_seal` and unseal.

## Replay, Fork, and Reset Compatibility

- Replay protection and fork detection run **after** the recipient unseals the inner package. They use the same logic as the non-sealed path (synthetic protocol envelope built from inner fields).
- Session reset is still triggered when replay or fork is detected on a sealed message; the sealed sender path does not bypass these checks.

## Limitations of This Prototype

- **Metadata minimization, not anonymity:** The design reduces what the relay learns (no plaintext sender in the outer envelope). It does not provide strong anonymity (e.g. against global traffic analysis or timing correlation).
- **Recipient locator:** The relay still sees who is the intended recipient. Hiding recipient or providing stronger anonymity would require additional mechanisms (e.g. private information retrieval, mix networks).
- **Routing:** Delivery depends on the correctness of `recipient_locator`; the server does not verify that the sender is authorized to send to that recipient.

## Delayed Routing and Dummy/Cover Traffic

- **Mix-style delay:** When enabled, the router holds envelopes in a RAM-only scheduled queue until `deliver_due(now)`; routing still uses only `recipient_locator`. No sender identity is required or stored.
- **Dummy and cover packets:** They use the same outer envelope format as real sealed sender traffic. The relay routes them by `recipient_locator` and stores them like any other envelope; it cannot tell them apart. The server remains payload-blind and sender-blind.

## Implementation Notes

- Use `get_routing_recipient(envelope)` to obtain the routing key; do not rely on any sender field for routing.
- Store only the outer envelope in the mailbox; do not attempt to parse or log the contents of `sp`.
- Ensure any logging or debugging does not expose `sp` or any decrypted material.
