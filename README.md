# GhostChat

GhostChat is a **research prototype** of an end-to-end encrypted messaging system for very small, trusted groups. It demonstrates a complete, documented security architecture: identity and prekeys, X3DH-style handshake, double ratchet, sealed sender, metadata hardening, and an MLS-inspired group protocol with epoch rotation.

**Status:** Educational / portfolio prototype. Not a production messenger. No formal or third‑party security review.

---

## 1. Project Overview

- **What it is:** A small, test-driven secure messaging stack built to be auditable and interview‑ready rather than feature‑complete. It focuses on correctness, clear invariants, and explicit limitations.
- **Design philosophy:** Keep the relay untrusted, keep keys on the endpoints, and be honest about what is and is not protected. The code is modular (crypto → ratchet → protocol → group → network hardening → relay), with each layer covered by targeted tests and documentation.
- **Prototype scope:** One-to-one sessions with double ratchet, sealed sender envelopes, replay/fork/reset handling, an in-memory relay with optional mix delay and cover/dummy traffic, and MLS-inspired small‑group messaging where membership changes trigger epoch rotation.

---

## 2. Key Security Features

- **Identity + prekeys**
  - Ed25519 identity keys as long-term identifiers.
  - X25519 signed prekeys (SPK) and one-time prekeys (OPKs).
  - SPK signatures are verified under the identity key before use; OPKs are consumed at most once.
- **Ratchet-based messaging**
  - X3DH-style handshake derives a shared root key.
  - Double ratchet provides forward secrecy and post-compromise security, with bounded skipped-key storage for out-of-order delivery.
- **Sealed sender concept**
  - Outer envelope exposes only `recipient_locator`, `ttl`, `sp` (sealed payload), and optional padding.
  - Inner package (sender_id, session_id, ratchet header, ciphertext) is encrypted with a key derived from the session root.
  - Relay does not need plaintext sender identity to route.
- **Replay / fork detection + reset**
  - Session-level replay cache (session_id, sender_ratchet_key, message_number).
  - Fork detection on regressions in message number or previous_chain_length.
  - On replay/fork, the session is marked for reset before any decryption attempt.
- **Group epoch rotation**
  - Group epoch starts at 1 and increments on every add/remove.
  - Tree-based key schedule derives per-epoch secrets and application keys.
  - New members cannot decrypt prior epochs; removed members cannot decrypt future epochs.
- **Metadata hardening**
  - Optional mix-style delay, cover traffic, and dummy packets, all using the sealed outer format.
  - Relay remains payload-blind and sender-blind in sealed sender mode.

---

## 3. Architecture Overview

Layers (see `docs/ARCHITECTURE_DIAGRAM.md` for ASCII diagrams and message paths):

- **Client layer:** `client/message_api.py`, `client/session_manager.py`, `client/group_manager.py` – in-memory endpoints used by tests and demos.
- **Crypto layer:** `crypto/identity.py`, `crypto/prekeys.py`, `crypto/x3dh.py`, HKDF helpers.
- **Ratchet layer:** `ratchet/double_ratchet.py`, skipped-key store – per-session forward secrecy and PCS.
- **Protocol layer:** `protocol/envelope.py`, `protocol/sealed_sender.py`, replay and fork detection, session reset state.
- **Group layer:** `group/group_state.py`, `group/group_messaging.py`, `group/membership.py`, `group/state_verification.py` – MLS-inspired epochs and membership.
- **Network hardening:** `network/mix_router.py`, `network/cover_traffic.py`, `network/dummy_packets.py`, `network/timing_defense.py`.
- **Relay server layer:** `server/router.py`, `server/memory_mailbox.py`, `server/ttl.py`, `server/websocket_server.py` (skeleton FastAPI entrypoint).
- **Storage layer:** `storage/encrypted_db.py` (design/abstraction; not fully wired into the demo).

---

## 4. Protocol Highlights

- **Handshake summary**
  - Hybrid X3DH-style handshake combines X25519 DH on identity/SPK/OPK with a pluggable PQ layer (interface only in this prototype).
  - SPK is signed by the identity key and verified before trust is established.
  - Both sides assert that classical (and PQ, when enabled) secrets match before deriving the root key via HKDF.
- **Ratchet summary**
  - Each pairwise session has a root key, sending and receiving chain keys, ratchet DH keys, message numbers, and a bounded skipped-key cache.
  - Messages are encrypted with per-message keys derived from the chain keys; old keys are discarded.
  - Replay and fork detection run before ratchet decrypt; protocol inconsistencies trigger session reset.
- **Group messaging model**
  - Small groups (3–6 members) share a `GroupState` with `group_id`, `epoch`, membership map, key tree, epoch secret, application key, and group hash.
  - Messages carry (group_id, epoch, sender_leaf_index, counter) and are encrypted with the application key for that epoch.
  - Replay cache keyed by (sender_leaf_index, counter); stale or divergent epochs are rejected and detected via group hash checks.

For full details see `docs/PROTOCOL_FLOW.md`, `docs/PROTOCOL_STATE_MACHINE.md`, and `docs/GROUP_PROTOCOL.md`.

---

## 5. Metadata Hardening

GhostChat adds a **best-effort** metadata hardening layer on top of sealed sender:

- **Mix delay**
  - `MixRouter` schedules envelopes with randomized delay; `Router.deliver_due(now)` moves due envelopes into mailboxes.
  - Breaks strict timing correlation between send and receive events.
- **Dummy packets**
  - `network/dummy_packets.py` creates sealed-sender-shaped dummies (same outer structure).
  - Relay routes them identically to real traffic; recipients drop them as undecryptable.
- **Cover traffic**
  - `network/cover_traffic.py` plus `message_api.get_pending_cover_packets` generate sealed cover envelopes on a configurable schedule.
  - Adds low-rate background noise so real bursts are less obvious.

Hardening never changes ciphertext semantics and does **not** provide strong anonymity. See `docs/NETWORK_HARDENING.md` and `docs/SERVER_SECURITY_NOTES.md` for details and limitations.

---

## 6. Quick Demo

This prototype is primarily **test-driven**. The easiest demo is via the test suite; optional scripts wrap common flows.

1. **Install dependencies**

```bash
cd ghostchat
python -m venv .venv
source .venv/bin/activate    # On Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. **Start a minimal relay (test-integrated)**

The relay is used in-process by tests via `server/router.Router` and `server/memory_mailbox.MemoryMailboxStore`. For a quick integration demo:

```bash
python -m pytest tests/test_protocol_integration.py::test_end_to_end_via_relay_router -v
```

3. **Run two “clients” and send a message**

Tests create two `SessionManager` instances (`alice` and `bob`) and exercise the message API:

```bash
python -m pytest tests/test_protocol_integration.py::test_protocol_integration_end_to_end -v
```

This covers:

- Session setup with a symmetric double ratchet (test helper).
- Alice sending an encrypted message.
- Bob decrypting and verifying the plaintext.

See `docs/DEMO_SCRIPT.md` for a full, step-by-step demo including replay rejection, sealed sender, mix delay, cover/dummy traffic, group creation, epoch rotation, and stale-epoch rejection.

---

## 7. Testing

Run the full test suite:

```bash
python -m pytest tests -v
```

This exercises:

- Identity and prekeys (`tests/test_identity.py`, `tests/test_prekeys.py`).
- X3DH handshake and ratchet basics (`tests/test_x3dh.py`, `tests/test_ratchet_basic.py`, `tests/test_ratchet_out_of_order.py`).
- Protocol envelope, replay protection, fork detection, and session reset (`tests/test_protocol_envelope.py`, `tests/test_replay_protection.py`, `tests/test_fork_detection.py`, `tests/test_protocol_integration.py`).
- Sealed sender and relay routing (`tests/test_sealed_sender.py`, `tests/test_protocol_integration.py`).
- Group state, membership, epoch rotation, and group messaging (`tests/test_group_state.py`, `tests/test_group_membership.py`, `tests/test_group_message_flow.py`, `tests/test_group_mls.py`, `tests/test_group_epoch.py`).
- Network hardening (mix, cover, dummy, timing) (`tests/test_mix_delay.py`, `tests/test_cover_traffic.py`, `tests/test_dummy_packets.py`, `tests/test_network_cover_and_dummy.py`, `tests/test_network_mix_and_timing.py`).

---

## Validation / How to Test

From the project root (`ghostchat/`):

1. **Install dependencies** (once):

   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Windows PowerShell: .venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

2. **Run full validation** (all test stages + PASS/FAIL summary):

   - Linux/macOS or Git Bash: `./scripts/validate_all.sh`
   - Windows PowerShell: `.\scripts\validate_all.ps1`

3. **Convenience targets** (optional; requires `make` on Windows or use the commands below):

   | Goal              | Command (make)   | Or run directly |
   |-------------------|-------------------|-----------------|
   | Run all tests     | `make test`       | `python -m pytest tests -v` |
   | Relay demo        | `make server`     | `python -m pytest tests/test_protocol_integration.py::test_end_to_end_via_relay_router -v` |
   | Client E2E demo   | `make client`     | `python -m pytest tests/test_protocol_integration.py::test_protocol_integration_end_to_end -v` |
   | Full validation   | `make validate`   | `./scripts/validate_all.sh` or `.\scripts\validate_all.ps1` |

4. **Demo scripts** (from `ghostchat/`): `scripts/demo_start_server.sh`, `scripts/demo_run_clients.sh`, `scripts/demo_group_flow.sh` run the same flows via pytest.

---

## 8. Current Limitations

- **Prototype status**
  - No production deployment story; relay and client are designed for local experiments.
  - WebSocket server (`server/websocket_server.py`) is a skeleton FastAPI app (health endpoint only).
- **Not production hardened**
  - No rate limiting or DoS controls beyond bounded caches and TTLs.
  - No formal or third‑party security audit.
- **Simplified MLS**
  - Group protocol is MLS-inspired but not MLS-compliant; fixed-size trees and small-group assumptions.
  - No full MLS transcript/hash semantics or asynchronous update schedules.
- **Simplified anonymity layer**
  - Sealed sender hides plaintext sender from the relay, but recipient, timing, and size remain visible.
  - Mix delay, cover, and dummy traffic are best-effort; no strong anonymity guarantees or global adversary resistance.
- **Key distribution and storage**
  - Prekey/identity distribution is not authenticated in this prototype.
  - Encrypted storage exists as an abstraction; no hardened key management or HSM integration.

See `docs/THREAT_MODEL.md`, `docs/ATTACK_SURFACE_ANALYSIS.md`, and `docs/FAILURE_MODE_ANALYSIS.md` for details.

---

## 9. Future Work

- **Stronger mixnet model**
  - Multi-hop routing, larger anonymity sets, and more aggressive cover traffic schedules.
  - Pluggable routing strategies that can approximate mixnet behavior in the lab.
- **Production key storage**
  - Encrypted local databases wired into the main client path.
  - Optional OS-backed key stores or hardware tokens for identity keys.
- **Full MLS compliance**
  - Move from MLS-inspired to spec-compliant groups (tree math, transcripts, proposals/commits).
  - Support for more dynamic group sizes and asynchronous updates.
- **Formal verification**
  - Apply model checking or symbolic analysis (e.g., Tamarin/ProVerif) to key protocol flows.
  - Extend test coverage with fuzzing of envelope and group message parsers.

---

## 10. Security Notice

GhostChat is a **prototype and educational system**. It uses well‑known cryptographic libraries (e.g. PyNaCl, `cryptography`), but the **overall protocol and implementation have not been formally verified or independently audited**. Do **not** rely on this code for real‑world sensitive communications without substantial additional review, hardening, and productionization. The security invariants, attack surface, and failure modes are documented in `docs/` to support such a review. 
