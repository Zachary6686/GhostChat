Architecture Diagram
====================

This document summarizes the high-level architecture of GhostChat for presentations and reviews. It reflects the current implementation structure.

Layer Diagram (Current Implementation)
--------------------------------------

```text
+-------------------+  +-------------------+  +-------------------+
|   Client Layer    |  |   Relay Server     |  |   Storage Layer   |
|  (message_api,    |  |   (router,         |  |  (encrypted_db    |
|   session_mgr,     |  |    mailbox,        |  |   abstraction)    |
|   group_mgr)       |  |    deliver_due)    |  |                   |
+---------+---------+  +---------+---------+  +-------------------+
          |                     ^
          v                     |
+---------+---------+  +---------+---------+
|  Protocol Layer   |  | Network Hardening  |
|  (envelope,       |  |  (mix_router,       |
|   sealed_sender,  |  |   cover_traffic,    |
|   replay, fork,   |  |   dummy_packets,    |
|   session_reset)  |  |   timing_defense)   |
+---------+---------+  +---------+---------+
          |
          v
+---------+---------+  +-------------------+
|  Ratchet Layer    |  |   Group Layer      |
|  (double_ratchet, |  |  (group_state,     |
|   skipped_keys)   |  |   key_schedule,    |
|                   |  |   membership,       |
+---------+---------+  |   group_messenger, |
          |            |   state_verification)|
          v            +-------------------+
+---------+---------+
|  Crypto Layer     |
|  (identity,       |
|   prekeys, x3dh)  |
+-------------------+
```

Top-Level Diagram
-----------------

```text
         +-------------------+                 +-------------------+
         |   Client A        |                 |   Client B        |
         |-------------------|                 |-------------------|
         |  UI / CLI         |                 |  UI / CLI         |
         |  Session Manager  |                 |  Session Manager  |
         |  Group Manager    |   Encrypted     |  Group Manager    |
         |  Crypto Engine    |<--------------->|  Crypto Engine    |
         |  Encrypted DB     |   Messages      |  Encrypted DB     |
         +---------+---------+                 +---------+---------+
                   ^                                     ^
                   |  WebSocket / TLS (sealed sender)    |
                   |                                     |
                   v                                     v
              +--------------------------+
              |        Relay Server      |
              |--------------------------|
              |  WebSocket Frontend      |
              |  RAM Mailboxes           |
              |  Mix Router              |
              |  Cover Traffic / Dummy   |
              |  Timing Defense          |
              +-------------+------------+
                            |
                            v
                  (No persistent storage)
```

Client Internal Structure
-------------------------

```text
+-------------------------------------------------------------+
|                        Client Node                          |
|-------------------------------------------------------------|
|  Application Layer                                          |
|   - UI / CLI                                                |
|   - Conversation & Group Views                              |
|                                                             |
|  Session & Group Layer                                      |
|   - Pairwise Session Manager (X3DH + Double Ratchet)        |
|   - Group Manager (MLS-inspired epochs & keys)              |
|                                                             |
|  Cryptographic Core                                         |
|   - Identity (Ed25519)                                      |
|   - Pre-Keys (SPK + OPKs, X25519)                           |
|   - Hybrid X3DH (classical + PQ abstraction)               |
|   - Double Ratchet (per-session)                            |
|   - Group Key Schedule (tree-based)                         |
|                                                             |
|  Transport & Network                                        |
|   - Sealed Sender Envelope Builder                          |
|   - WebSocket/TLS Client                                    |
|                                                             |
|  Encrypted Storage                                          |
|   - Encrypted DB (identities, sessions, groups, history)    |
+-------------------------------------------------------------+
```

One-to-One Message Path (Current Implementation)
------------------------------------------------

```text
Sender                                                    Recipient
------                                                    ---------
message_api.send_text()
    |
    v
session_manager.encrypt_sealed()  [or encrypt_for() for non-sealed]
    |
    +-> double_ratchet.encrypt() --> header + ciphertext
    +-> sealed_sender.seal(inner) --> sp
    +-> SealedOuterEnvelope(recipient_locator, ttl, sp, pad)
    |
    v
[optional: mix_router.schedule_envelope(); cover_traffic; dummy]
    |
    v
transport --> Relay (router.enqueue_by_envelope)
                    |
                    +-> get_routing_recipient(envelope) --> recipient_locator
                    +-> mailbox[recipient].enqueue(env)
                    +-> [optional] deliver_due(now) for mix delay
                    |
    transport <------+
    |
    v
message_api.recv_sealed(drop_undecryptable=True)
    |
    +-> sealed_sender.unseal(sp) --> inner (sender_id, session_id, header, ct)
    +-> replay_protection.SessionReplayCache.accept()
    +-> fork_detection.detect_fork()
    +-> session_reset.mark_for_reset() on failure
    +-> double_ratchet.decrypt(header, ct) --> plaintext
    |
    v
message_api delivers plaintext to app
```

Group Message Path (Current Implementation)
-------------------------------------------

```text
Sender (group member)                                    Recipients
-------------------                                    -----------
message_api.send_group_text(group_id, body)
    |
    v
group_manager.send_message() --> GroupMessenger.encrypt()
    |
    +-> GroupState: epoch, application_key, group_hash, tree
    +-> header = (group_id, epoch, sender_leaf_index, counter)
    +-> AEAD(application_key, plaintext, header)
    +-> GroupMessage.to_dict()
    |
    v
[wrap in envelope with recipient_locator = group_id or group mailbox]
    |
    v
transport --> Relay --> mailboxes (group or per-member)
    |
    v
message_api.recv_group_text() <-- transport
    |
    v
group_manager.recv_message() --> GroupMessenger.decrypt()
    |
    +-> header.group_id == state.group_id
    +-> header.epoch == state.epoch  [stale epoch rejected]
    +-> sender_leaf_index in members
    +-> replay cache (sender_leaf_index, counter)
    +-> AEAD decrypt with state.application_key
    |
    v
plaintext delivered to app
```

Security Boundaries
-------------------

- **End-to-End Boundary:** Client crypto/ratchet to peer crypto/ratchet; relay sees only opaque ciphertext and recipient_locator.
- **Relay:** RAM-only; no persistent message storage; no decryption; no sender identity in sealed sender mode.
- **Storage:** Encrypted DB abstraction; no plaintext session keys in long-term storage by design.

This document can be used as a slide in a final-year project or portfolio to explain the separation between client, cryptographic core, and untrusted relay. 

