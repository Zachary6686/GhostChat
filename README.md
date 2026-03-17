# GhostChat

## 1. Overview

GhostChat is a small-group secure messaging prototype focused on correctness, explicit security invariants, and threat-model-driven design. It implements X3DH-style session establishment and the Double Ratchet algorithm for message-layer security. The relay is untrusted; encryption keys never leave the endpoints.

The stack uses AEAD (ChaCha20-Poly1305) for transport encryption, strict parsing and validation for wire and persisted state, and explicit replay and anti-rollback protections. Session state is stored in JSON files under a single-writer, atomic-write model. The project is test-driven and documents its security invariants and trade-offs explicitly. It is not production-ready and has not been formally verified or independently audited.

## 2. Threat Model

**Attacker capabilities the implementation addresses:**

- **MITM on the relay:** Interception, modification, or replay of ciphertexts. Mitigated by AEAD (integrity), AAD binding of header fields, and a bounded replay cache keyed by (dh, n). Replayed or modified messages either fail decryption or are rejected as duplicates when (dh, n) is still in the cache.
- **Malformed inputs:** Invalid wire messages or persisted session data. Mitigated by strict parsing: required fields, types, lengths, and ranges are enforced; malformed data raises explicit errors (e.g. `InvalidHeaderError`, `CorruptedSessionError`) and is never silently accepted.
- **Replay:** Re-submission of previously accepted messages. Mitigated by `ReceivedIdsStore` (bounded FIFO of (dh, n)) and by ratchet ordering checks (e.g. n < Nr). A bounded replay cache protects recent messages from re-acceptance; very old replays may fall outside this cache (see Trade-offs).
- **Downgrade (hybrid PQ):** If a hybrid algorithm suite is used, the implementation rejects classical-only material when the peer advertises hybrid, and rejects hybrid material when the peer is classical-only (`AlgorithmSuiteMismatchError`). The PQ backend is pluggable; the shipped backend is a non-cryptographic dummy.
- **Local session file tampering:** Corrupted or rolled-back session files. Mitigated by strict deserialization (fail closed), monotonic `session_version`, and anti-rollback on save (`SessionRollbackError`). Invalid JSON in an existing file causes save to raise rather than overwrite.

**Out of scope / not guaranteed:**

- **Metadata privacy:** Recipient, timing, and message size can be observed by the relay. Sealed-sender-style envelopes reduce sender visibility to the relay but do not provide strong anonymity.
- **Large-scale anonymity:** No mixnets or global-adversary guarantees.
- **Side-channel resistance:** No constant-time or hardened implementation claims; standard libraries (e.g. PyNaCl, `cryptography`) are used as-is.

## 3. Protocol Architecture

### Initialization

Session establishment follows an X3DH-style handshake:

- **Identity:** Ed25519 long-term identity key; public key is the client identifier.
- **Prekeys:** X25519 signed prekey (SPK) and one-time prekeys (OPKs). SPK is signed with the identity key and verified before use; OPKs are consumed at most once (reuse raises `OneTimePreKeyReuseError`).
- **Handshake:** Shared secret from DH (IK_A×SPK_B, EK×IK_B, EK×SPK_B, optionally EK×OPK_B); HKDF derives the root key. A canonical transcript (identity publics, SPK, ephemeral, OPK id, and optionally algorithm suite) is hashed and bound into root-key derivation so both sides derive identical key material and downgrade or parameter tampering is detectable.

### Message Layer

- **Double Ratchet:** Per-session state includes root key, sending and receiving chain keys, and DH ratchet keys (local `dhs_private`, remote `dhr`). Counters Ns (sent), Nr (received), and PN (previous chain length) are maintained. On send, a message key is derived from the sending chain key and used once; header (dh, n, pn) is sent with the ciphertext. On receive, duplicate (dh, n) is rejected; out-of-order messages within a bounded window use stored skipped message keys; a new remote DH key triggers a DH ratchet step (root key and chains updated, new local DH key generated).
- **Symmetric chains:** Message keys are derived via HKDF with domain-separated context (root, chain, initial-chain). Each message uses a distinct key; keys are not reused.

### Encryption

- **AEAD:** ChaCha20-Poly1305 (32-byte key, 12-byte nonce). Ciphertext includes the authentication tag.
- **AAD:** Header fields (dh, n, pn) are encoded deterministically (32-byte dh, then n and pn as big-endian uint32) and passed as associated data. Tampering with any of these causes authentication failure at decryption.

### Hybrid PQ (optional, scaffolded)

- An optional PQC KEM layer can be combined with X25519 during the handshake. The codebase defines a `PQKEMBackend` protocol and a **non-cryptographic** dummy backend for tests. Algorithm suite is bound in the transcript; downgrade or suite mismatch is rejected. **Production post-quantum security requires replacing the dummy with a real ML-KEM/Kyber (or equivalent) implementation;** the current dummy must not be used for real traffic.

## 4. State Machine Summary

- **Core state:** `root_key`; `sending_chain_key` / `receiving_chain_key`; `dhs_private` (local DH), `dhr` (remote DH public); `Ns`, `Nr`, `PN`; `skipped_message_keys` (bounded map (dh, n) → message key); `received_ids` (bounded FIFO of (dh, n)); `session_version` (monotonic).
- **Send:** Require sending chain key (derive from root + dhr if needed). Derive message key from chain key; build header (dh = local public, n = Ns, pn = PN); encrypt with AEAD and AAD; increment Ns.
- **Receive:** Reject if (dh, n) in `received_ids`. If (dh, n) in `skipped_message_keys`, pop key, decrypt, add to `received_ids`, return. If new remote key (header.dh ≠ dhr), perform DH ratchet (set PN = Ns, reset Ns/Nr, update root and chains, new dhs_private). Reject if n < Nr or if n − Nr > MAX_SKIP_DISTANCE. Advance receiving chain to n (storing skipped keys), derive message key for n, decrypt, add (dh, n) to `received_ids`, set Nr = n + 1.
- **Replay / skipped keys:** Replay of (dh, n) within `received_ids` is rejected. Out-of-order delivery uses keys stored in `skipped_message_keys`; each key is used at most once (popped on decrypt). Bounded FIFO eviction applies to both `received_ids` and `skipped_message_keys` and affects replay tracking only; forward secrecy and ratchet correctness remain intact.

## 5. Security Properties

- **Forward secrecy:** DH ratchet and per-message keys; compromise of long-term keys does not make past message keys recoverable.
- **Post-compromise security:** New DH ratchet steps derive new root and chain keys; keys for messages sent after a compromise are not derivable from earlier compromised state.
- **Authenticated encryption:** ChaCha20-Poly1305 with AAD; ciphertext and header fields are jointly authenticated, and decryption fails on any modification.
- **Replay protection (bounded):** Recent (dh, n) pairs are stored and replayed messages with those identifiers are rejected; very old messages may fall outside the cache (see Trade-offs).
- **Anti-rollback persistence:** `session_version` is monotonic; save refuses to overwrite if on-disk version is higher, so older state cannot silently replace newer state.
- **Strict parsing / fail-closed:** Wire and session parsing enforce types, lengths, and ranges; invalid or missing data raises explicit exceptions; malformed input does not produce usable session or plaintext.

## 6. Explicit Trade-offs

### Bounded replay cache

- **Recent replay:** Messages whose (dh, n) is still in `ReceivedIdsStore` (FIFO, default 2000 entries) are rejected. Persisted across save/load.
- **Very old messages:** Once more than 2000 (dh, n) entries exist, the oldest are evicted. Replay of a message that has been evicted is not guaranteed to be rejected by the cache alone; ratchet ordering (e.g. n < Nr) still constrains exploitability. The design trades unbounded replay history for bounded memory. This is an explicit engineering trade-off, not a protocol failure.

### Single-writer session persistence

- Session files (JSON under `sessions/`) are written with an atomic write (temp file + rename). There is no multi-process or multi-writer coordination. Concurrent access to the same session file can corrupt state; the implementation assumes a single writer per session file.

### DoS limits

- **Ciphertext size:** Wire message parser rejects ciphertext larger than 1 MiB (`MAX_CIPHERTEXT_LEN`).
- **WebSocket message size:** Relay rejects raw WebSocket text frames larger than 2 MiB (`MAX_WEBSOCKET_MESSAGE_BYTES`) before JSON parsing.
- **Skip distance:** Incoming message number n cannot exceed Nr + `MAX_SKIP_DISTANCE` (5000); larger gaps are rejected to bound CPU and memory.

## 7. Testing & Verification

The project uses pytest for unit and integration tests. Optional Hypothesis-based tests (when the `hypothesis` package is installed) add property and fuzz coverage.

**What is tested:**

- **Parser robustness:** Wire message, session state, and bundle parsing are exercised with valid and malformed inputs. Invalid base64, wrong types, missing fields, and out-of-range values must raise the intended errors (`InvalidHeaderError`, `CorruptedSessionError`, `ValueError`); no silent acceptance.
- **State-machine invariants:** Double Ratchet tests cover encrypt/decrypt round-trips, replay rejection, out-of-order delivery within the skipped-key window, skip-distance rejection, and AAD/header tampering (decryption must fail).
- **Replay behavior:** Duplicate (dh, n) is rejected before key derivation; replay after save/load is still rejected when (dh, n) remains in the cache; eviction semantics are tested.
- **Persistence:** Round-trip serialize/deserialize preserves security-relevant fields; mutated or corrupted persisted state is rejected; anti-rollback on save is tested.

Property-based tests validate invariants and failure modes across many traces, not just fixed example scenarios.

**Representative test modules:** `test_double_ratchet_client.py`, `test_x3dh_client.py`, `test_fuzz_wire_message.py`, `test_fuzz_session_state.py`, `test_property_double_ratchet.py`, `test_protocol_integration.py`. Validation scripts: `scripts/validate_all.sh`, `scripts/validate_all.ps1`.

The implementation is not formally verified. Tests are intended to catch regressions and to document expected fail-closed behavior.

## 8. Limitations

- **Not production-ready:** No deployment story, no SLAs, no security audit. For education and security review practice only.
- **No multi-device sync:** Session state is per-process; no design for consistent state across devices.
- **No metadata protection:** Relay can observe recipient, timing, and size; sealed-sender reduces but does not eliminate sender visibility.
- **No real PQ backend:** Post-quantum support is an interface plus a non-cryptographic dummy; production PQ requires a certified KEM implementation.
- **Single-writer sessions:** Concurrent writes to the same session file are unsupported.
- **Key distribution:** Prekey/bundle distribution is assumed trusted in this prototype and is not authenticated by the protocol itself.

## 9. Development Notes

- **Single-threaded assumption:** The Double Ratchet and session code do not assume thread-safe access; one logical writer per session is expected.
- **Session storage:** File-based JSON under `sessions/`; path derived from local and remote usernames. No database or HSM integration in the main path.
- **Intended usage:** Small, trusted groups; lab or local relay. CLI connects to a WebSocket relay (e.g. `uvicorn server.websocket_server:app`); run tests with `python -m pytest tests -v`.

**Quick start:** Install dependencies (`pip install -r requirements.txt`); run tests (`python -m pytest tests -v`); start relay and clients as in the previous README or `docs/DEMO_SCRIPT.md` if present.

---

**Security notice:** Do not use this code for real sensitive communications. Protocol and implementation have not been formally verified or independently audited. Use only after review and hardening appropriate to your threat model.
