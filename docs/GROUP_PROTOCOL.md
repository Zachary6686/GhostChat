GROUP PROTOCOL (SIMPLIFIED MLS-INSPIRED)
========================================

This document describes the simplified MLS-style group messaging layer used in GhostChat. It is intended for small, trusted groups (3–6 members) and is **not** a full implementation of the MLS specification.

Overview
--------

The group protocol extends the existing identity and double-ratchet system with:

- A shared **group state** per group.
- A tree-based **key schedule** that derives per-epoch secrets.
- **Membership operations** (add/remove) that trigger epoch changes.
- A symmetric **application key** for encrypting group messages.

Group State Model
-----------------

Each group maintains the following state:

- `group_id`: opaque group identifier (bytes).
- `epoch`: monotonically increasing integer; increments on any membership change.
- `members`: mapping from identity public key (Ed25519) to `leaf_index`.
- `tree`: fixed-capacity binary tree of node secrets used in the key schedule.
- `group_secret` (epoch_secret): HKDF-derived secret for the current epoch.
- `application_key`: symmetric key used to encrypt group messages in this epoch.
- `group_hash`: commitment to `group_id`, `epoch`, membership list, and tree root.

The state is serializable (`group/serialization.py`) so it can be stored in encrypted client storage and reconstructed later.

Key Schedule
------------

The key schedule is defined in `group/key_schedule.py` and operates as follows:

1. **Leaf secrets**
   - Each member has a randomly generated 32-byte leaf secret.
   - A per-leaf node secret is derived via HKDF:
     - `leaf_node_secret = HKDF(leaf_secret, "ghostchat-group-leaf:<index>")`

2. **Internal node secrets**
   - The tree is a full binary tree with up to 4 leaves (prototype limit).
   - Each internal node secret is derived from its two children:
     - `node_secret = HKDF(left_secret || right_secret, "ghostchat-group-node:<i>")`

3. **Epoch secret (group_secret)**
   - The root node secret and `group_id` feed another HKDF:
     - `epoch_secret = HKDF(root_secret, "ghostchat-epoch-secret:<epoch>")`
   - In code this value is stored as `group_secret`.

4. **Application key**
   - The application key is derived from the epoch secret:
     - `application_key = HKDF(epoch_secret, "ghostchat-app-key")`

5. **Group hash**
   - A commitment used for consistency checks:
     - `group_hash = HKDF(group_id || epoch || member_ids || root_secret, "ghostchat-group-hash")`

Membership Changes and Epochs
-----------------------------

### Group Creation

1. A new `group_id` is chosen.
2. For each initial member, a random leaf secret is generated.
3. Leaf node secrets are derived and placed into the tree.
4. Unused leaves are filled with deterministic padding derived from `group_id`, ensuring a defined root even for small groups.
5. The root secret is computed, then the first `epoch_secret`, `application_key`, and `group_hash` are derived.
6. `epoch` is set to `INITIAL_EPOCH` (1).

### Member Add

When a new member joins:

1. A new leaf index is assigned and a fresh leaf secret is generated.
2. The leaf node secret for the new member is placed in the tree.
3. Parent node secrets along the path to the root are recomputed using HKDF.
4. The group’s `epoch` is incremented.
5. A new `epoch_secret`, `application_key`, and `group_hash` are derived.

Security property:

- A joining member receives only the post-join group state (epoch `e+1`). Since they never see previous epoch secrets, they cannot decrypt messages from epochs `< e+1`.

### Member Remove

When a member is removed:

1. The removed member is deleted from the membership map.
2. Their leaf node is overwritten with a fresh random secret (update secret).
3. Parent node secrets along the path to the root are recomputed.
4. The group’s `epoch` is incremented.
5. A new `epoch_secret`, `application_key`, and `group_hash` are derived.

Security property:

- The removed member does not know the new leaf secret or updated tree secrets, so they cannot compute subsequent epoch secrets or decrypt future group messages.

Group Messaging
---------------

Group messaging is implemented in `group/group_messaging.py`.

- Each participant uses the current `application_key` from their `GroupState`.
- A sender maintains a local `message_counter` per group.
- Each message carries a header:
  - `group_id`
  - `epoch`
  - `sender_leaf_index`
  - `message_counter`
- The payload is encrypted with ChaCha20-Poly1305 using:
  - Key: `application_key`
  - Nonce: derived from `application_key` and `message_counter`
  - Associated data: header fields and optional application-specific data

On receipt:

1. The receiver checks that `group_id` matches their group.
2. The receiver checks that `epoch` matches their current epoch. Stale or future epochs are rejected.
3. The receiver checks that `sender_leaf_index` corresponds to a known member.
4. The receiver uses a replay cache of `(sender_leaf_index, message_counter)` to reject duplicates.
5. The receiver decrypts using the `application_key` and validated header.

State Verification
------------------

Group state verification is implemented in:

- `group/state_verification.py`
- `group/epoch_manager.py`

Each client can:

- Compute a `GroupStateSummary` from its local state:
  - `group_id`, `epoch`, `group_hash`, sorted `member_ids`.
- Compare summaries received from peers:
  - Reject if group IDs differ.
  - Reject if epochs differ.
  - Reject if group hashes differ.
  - Reject if membership lists differ.
- Optionally check that the current epoch is ≥ the last known epoch (monotonicity).

If any of these checks fail, the client treats the group state as **inconsistent** and must trigger a resynchronization (e.g., by requesting a fresh authoritative group state from a trusted peer).

Structured validation is available via `validate_local_state(state)`, `validate_incoming_state(local_summary, remote_summary)`, and `validate_serialized(data)`; they return `ValidationResult(success, errors)`. Malformed serialized state raises `InvalidGroupStateError` on deserialize.

Replay and consistency handling
-------------------------------

- **Replay:** `GroupMessenger` uses a bounded `ReplayCache` keyed by `(sender_leaf_index, counter)`. Duplicate messages raise `ReplayedGroupMessageError`. Cache has a configurable `max_entries` to avoid unbounded growth.
- **Stale epoch:** Messages with `epoch != state.epoch` raise `EpochMismatchError`.
- **Invalid member:** Unknown `sender_leaf_index` raises `MembershipError`.
- Invalid group traffic must not corrupt valid local state; decryption failures surface as these errors rather than mutating state.

Client integration
------------------

- **GroupManager** (client/group_manager.py): Holds group state per `group_id`. `create_group(group_id, member_ids)`, `add_group_member`, `remove_group_member`, `get_messenger(group_id)`, `get_receiver(group_id)`, `join_group(group_id, state, my_leaf_index)` for members added by others.
- **Message API:** `send_group_text(profile, group_id, text, member_profiles)` encrypts and appends to each member's group_inbox; `recv_group_text(profile, group_id)` decrypts pending group messages. Envelopes use `recipient_locator` (e.g. b64 group_id) and `group_message` payload (serialized `GroupMessage.to_dict()`).
- **Relay:** Group messages can be routed by `recipient_locator` like sealed sender; the relay remains payload-blind.

Security Limitations vs Real MLS
--------------------------------

This design is intentionally simplified and has several limitations compared to the MLS standard:

- **Fixed small tree**: The tree is fixed to a small maximum group size and does not support arbitrary dynamic rebalancing.
- **Single application key**: All members in an epoch share a single symmetric application key, rather than per-sender or per-message secrets.
- **No asynchronous key packages**: The prototype omits MLS key packages, credential structures, and extensions.
- **No transcript-based authentication**: The protocol does not maintain or sign a full transcript of group operations as MLS does.
- **No formal ciphersuite negotiation**: Algorithm choices are fixed (HKDF-SHA256, ChaCha20-Poly1305, X25519/Ed25519 from the underlying system).
- **Limited group size**: The implementation is only intended for very small, trusted groups and has not been optimized or proven for large-scale deployments.

Despite these limitations, the implementation preserves key MLS-inspired properties for small groups:

- Adding a member rotates the epoch and keys so they cannot decrypt prior messages.
- Removing a member rotates the epoch and keys so they cannot decrypt future messages.
- Group state consistency is explicitly verifiable via a group hash and epoch tracking.

