Architecture Overview
======================

GhostChat is structured as a set of small, focused modules intended to be **auditable** and **testable**. The system is designed for a very small, trusted group of users and runs as a local prototype rather than a production service.

This document summarizes only the pieces relevant to **Phase 1 (identity + pre-keys)**. Later phases extend the same structure.

## High-Level Layers

- **`crypto/`**: Low-level cryptographic primitives and key management.
- **`ratchet/`**: Double-ratchet state machine and key derivation (future phases).
- **`protocol/`**: Envelopes, replay protection, fork detection, and sealed sender. Sealed sender provides an outer envelope (recipient_locator, ttl, opaque `sp`) and an inner protected package (sender_id, session_id, ratchet header, ciphertext) encrypted with a session-derived sealing key so the relay never sees sender identity.
- **`network/`**: Optional metadata hardening: mix-style delayed routing (`MixRouter`), dummy packets (sealed outer shape), cover traffic (client hook), timing jitter and batching (`TimingDefenseConfig`, `DelayStrategy`). Deterministic configs for tests.
- **`server/`**: RAM-only relay; routing by `recipient_locator` only. Optional `MixRouter` for delayed delivery (`deliver_due`); dummy/cover traffic uses same envelope shape.
- **`client/`**: Client bootstrap, session manager, message API; cover traffic hook; **GroupManager** for group state and group send/receive (`create_group`, `add_group_member`, `remove_group_member`, `send_group_text`, `recv_group_text`).
- **`storage/`**: Encrypted local database abstraction (future phases).
- **`transport/`**: TLS and obfuscation hooks (future phases).

## Phase 1 Components

### Identity Keys (`crypto/identity.py`)

- Generates and manages **Ed25519** identity key pairs.
- The **public identity key** is the stable account identifier.
- Provides:
  - Key generation.
  - Serialization to a compact, unambiguous binary format (and Base64 helpers).
  - Signature and verification helpers used by the pre-key system.

### Pre-Keys (`crypto/prekeys.py`)

- Manages X25519 **signed pre-keys (SPK)** and **one-time pre-keys (OPKs)**.
- Uses:
  - X25519 key pairs for DH.
  - Ed25519 identity key to sign the SPK.
- Responsibilities:
  - Generate a fresh SPK bound to the identity key via an Ed25519 signature.
  - Generate a batch of OPKs for one-time use.
  - Consume OPKs in a strictly one-time manner, tracking which are used.
  - Serialize/deserialize SPKs and OPKs with explicit structure and versioning.

### Serialization (`crypto/serialization.py`)

- Provides small helpers for:
  - Base64-url encoding / decoding of binary keys and signatures.
  - Version-tagged serialization formats for identity keys and pre-keys.
- The formats are intentionally simple and explicit (no pickling, no implicit magic).

### Errors (`crypto/errors.py`)

- Centralizes crypto-related exceptions for Phase 1:
  - Invalid signatures.
  - Unknown or invalid key formats.
  - Exhausted or missing OPKs.

## Data Flow (Phase 1)

1. A client creates an identity key pair using `IdentityKeyPair.generate()`.
2. The client creates a `PreKeyBundle`:
   - Generates an X25519 SPK.
   - Signs the SPK public key with the Ed25519 identity secret key.
   - Generates a batch of OPKs (X25519 key pairs).
3. The pre-key bundle is serialized for publication (e.g., to a directory service in later phases).
4. Peers later use this material to perform an X3DH-style handshake (Phase 2).

The **identity key** is the root of trust; **SPK/OPKs** are semi-ephemeral authentication and forward-secrecy material derived from it.

