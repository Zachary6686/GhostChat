# GhostChat Security Audit

**Scope:** Client crypto (Double Ratchet, X3DH, AEAD, KDF), session persistence, wire format, PQC hybrid handshake, and related validation.

**Method:** Static review of implementation against stated invariants and realistic attack scenarios. No fuzzing or formal verification.

---

## 1. Cryptographic Correctness

### 1.1 AEAD Usage

**Finding: Correct.**  
`client/crypto/symmetric.py` uses ChaCha20-Poly1305 with 32-byte keys and 12-byte nonces. Key and nonce length are validated before use. `aead_decrypt` docstring correctly states that `InvalidTag` is raised on any authentication failure (tag mismatch, wrong AAD, or corruption). AAD is passed through and bound to the ciphertext.

### 1.2 Nonce Handling

**Finding: Correct.**  
Nonces are derived in `double_ratchet.py` via `_message_key_to_nonce(mk, n)`: 12 bytes from the message key, with the last 4 bytes XORed with the message number `n`. Each (chain position, message number) therefore gets a distinct nonce. Nonces are not reused across messages; they are deterministic and verified on decrypt (comparison with `msg.nonce`).

### 1.3 Key Reuse Risks

**Finding: No reuse identified.**  
Message keys are derived once per message from the chain KDF, used for a single AEAD operation, and never persisted as long-term keys. Skipped message keys are popped after use. Root and chain KDFs use distinct domain separation (see 1.4).

### 1.4 KDF Domain Separation

**Finding: Correct.**  
`client/crypto/kdf.py` uses fixed salts and info strings: `ROOT_INFO`/`ROOT_SALT`, `CHAIN_INFO`/`CHAIN_SALT`, `FIRST_SEND_INFO`. Root KDF uses `root_key` as salt when non-empty. X3DH uses `X3DH_SALT`/`X3DH_INFO` and `X3DH_ROOT_SALT`/`X3DH_ROOT_INFO + th`. Hybrid combination uses `HYBRID_COMBINE_SALT` and distinct info for classical vs hybrid (`CLASSICAL_ONLY_INFO` vs `HYBRID_COMBINE_INFO`). No overlap between contexts.

---

## 2. Double Ratchet Correctness

### 2.1 DH Ratchet Transitions

**Finding: Correct.**  
New remote DH public key triggers `_dh_ratchet_receive` or `_dh_ratchet_receive_first`: root key is updated via `kdf_root`, receiving chain is set, and on receive PN is set to Ns, Ns/Nr zeroed, and a new sending DH pair generated. Sending side performs `_dh_ratchet_step_send` when `sending_chain_key` is None, deriving sending chain from root and current DH.

### 2.2 Ns / Nr / PN Correctness

**Finding: Correct.**  
Ns is incremented after each send; Nr after each successful receive. PN is set to the previous Ns when the receiving ratchet turns (`_dh_ratchet_receive`). Header carries (dh, n, pn) and is bound as AAD.

### 2.3 Skipped Key Handling

**Finding: Correct.**  
Out-of-order messages cause the receiver to advance the receiving chain with `_skip_receiving_until(h.n)`, storing message keys in `SkippedMessageKeys` for indices before `h.n`. When a message arrives with a stored skipped key, that key is popped (single use), nonce is derived and checked, and AEAD decrypt runs with header AAD. Keys are 32 bytes; index is (dh_pub, n). FIFO eviction when at capacity (max 1000) is implemented.

### 2.4 Out-of-Order Logic

**Finding: Correct.**  
Duplicate/replay is checked first via `received_ids.contains(h.dh, h.n)`. Then the skipped-key path is tried. Then DH ratchet and receiving chain advancement with skip distance check (`MAX_SKIP_DISTANCE = 5000`). Then one-step chain derivation for the current `h.n`. Ordering of checks and state updates is consistent.

---

## 3. Replay & Duplicate Protection

### 3.1 Message Identity Robustness

**Finding: Robust.**  
Replay is keyed by `(dh, n)` where `dh` is 32-byte ratchet public key and `n` is message number. Identity is encoded in `ReceivedIdsStore` as base64(dh || n big-endian) and decoded with strict length check (36 bytes). Duplicate is checked before any key derivation or decryption.

### 3.2 Bypass Possibilities

**Finding: One limitation (medium).**  
`ReceivedIdsStore` is bounded (max 2000 entries) with FIFO eviction. On load, `from_dict` adds all persisted IDs; if there are more than 2000, older ones are evicted. Therefore, a message that was previously accepted but whose (dh, n) was evicted (e.g. after a save/restore with many newer messages) could be accepted again if replayed. The window is limited to messages older than the 2000 most recent received IDs.

**Recommendation:** Document this as an accepted trade-off (bounded storage vs. replay window for very old messages). Optionally add a maximum message age or explicit “replay window” in the spec.

---

## 4. AAD Canonicalization

### 4.1 Deterministic Encoding

**Finding: Correct.**  
`_header_aad(header)` in `double_ratchet.py` builds exactly: `header.dh` (32 bytes) || `header.n` as 4 bytes big-endian || `header.pn` as 4 bytes big-endian. No structural ambiguity; same header always yields the same AAD.

### 4.2 Mismatch Resistance

**Finding: Correct.**  
Any change to dh, n, or pn changes AAD and causes ChaCha20-Poly1305 to fail with `InvalidTag`. Nonce is also checked explicitly against the derived nonce, so header tampering is rejected even if an attacker could force a nonce match.

---

## 5. Anti-Rollback Protection

### 5.1 Rollback Detection

**Finding: Correct.**  
On `save_session`, the existing file (if any) is read and `session_version` is parsed. If `file_version > current_version` (in-memory), `SessionRollbackError` is raised and the file is not overwritten. So a newer state on disk cannot be replaced by an older in-memory state. The in-memory version is then incremented and written. Monotonicity is enforced on write, not on read.

### 5.2 Corrupted File on Save

**Finding: Acceptable behavior.**  
If the existing session file is not valid JSON, the code catches `json.JSONDecodeError` and proceeds with the save (overwrite). So a corrupted file is treated as “no valid existing version” and is replaced. This is a repair behavior; the only risk is accidental overwrite if the file was corrupted by I/O.

**Recommendation:** Consider logging or a distinct error when the file exists but is not valid JSON, so operators can detect corruption.

---

## 6. Transcript Binding

### 6.1 Completeness

**Finding: Correct.**  
X3DH transcript in `_build_transcript` includes: `ik_a_pub`, `ik_b_pub`, `spk_b_pub`, `eph_pub`, `opk_id` (4 bytes, 0xFFFFFFFF if none), and for hybrid `algorithm_suite`. Initiator and responder use the same logical order. Transcript hash `th` is fed into root key derivation (HKDF info: `X3DH_ROOT_INFO + th` and for hybrid `+ algorithm_suite`). So the root key is bound to the full handshake and algorithm choice.

### 6.2 Algorithm / Downgrade Protection

**Finding: Correct.**  
Hybrid sessions include `algorithm_suite` in the transcript and in root KDF info. Classical path does not include it (backward compatible). Responder requires `pq_ciphertext` and hybrid suite when the bundle is hybrid; rejects when bundle is classical but initiator sends PQ material. Initiator requires `pq_backend` when the peer bundle is hybrid. Downgrade to classical when the peer supports hybrid is rejected.

---

## 7. X3DH Handshake

### 7.1 Signature Verification

**Finding: Correct with one code-quality note.**  
SPK is verified with `IdentityKeyPair.verify(self.public_key, spk_pub, spk_sig)`. In `_verify_spk_signature` the initiator only has the peer’s identity public key; the code constructs `IdentityKeyPair(public_key=identity_pub, private_key=bytes(KEY_LEN))` (32 zero bytes) and calls `verify()`, which uses only `verify_key` (public key). So verification is correct. The dummy private key is never used for signing but could be confusing or misused in refactors.

**Recommendation (low):** Prefer a “verify-only” API (e.g. `VerifyKey(identity_pub).verify(spk_pub, spk_sig)`) or clearly document that the private key is not used in this path.

### 7.2 Prekey Consumption

**Finding: Correct.**  
`consume_one_time_prekey(key_id)` in `client/crypto/prekey.py` checks `used_opk_ids`, then pops the OPK; if missing, raises `OneTimePreKeyReuseError`. It then appends `key_id` to `used_opk_ids`. So each OPK is consumed at most once and reuse is rejected.

### 7.3 First-Message Validation

**Finding: Correct.**  
`_validate_peer_bundle` checks types and lengths (identity_pub, identity_dh_pub, spk_pub, spk_sig 64 bytes, OPK lengths and ids). SPK signature is verified before any DH. Initiator and responder validate key lengths and presence of required fields; empty `pq_ciphertext` is rejected on the responder in hybrid mode.

---

## 8. PQC Hybrid Design

### 8.1 Downgrade Resistance

**Finding: Correct.**  
Hybrid is required when the peer bundle has `pq_pub` and a hybrid `algorithm_suite`; initiator must have `pq_backend` and sends `pq_ciphertext`; responder requires `pq_ciphertext` and matching suite when the bundle is hybrid. Classical responder rejects PQ material; hybrid responder rejects missing or classical-only suite.

### 8.2 Key Combination

**Finding: Correct.**  
`combine_shared_secrets` uses HKDF with distinct info/salt for classical-only vs hybrid. Hybrid path concatenates `classical_shared + pq_shared` and derives 32 bytes; no raw concatenation as key. Domain separation prevents mixing classical-only and hybrid outputs.

### 8.3 Malformed Input

**Finding: Correct.**  
Empty `pq_ciphertext` is rejected in the responder. Algorithm suite mismatch raises `AlgorithmSuiteMismatchError`. `combine_shared_secrets` raises if `pq_shared` is None but suite is not classical.

### 8.4 PeerBundle When `pq_pub` Present and `algorithm_suite` Missing

**Finding: Inconsistent state, low severity.**  
In `PeerBundle.from_dict`, if the server sends `pq_pub` but omits `algorithm_suite`, `algorithm_suite` defaults to `ALGORITHM_SUITE_CLASSICAL`. The initiator then does classical-only (no `pq_ciphertext`). The responder (with a full hybrid bundle) expects `pq_ciphertext` and rejects. So there is no silent downgrade, but handshake fails. A MITM could strip `algorithm_suite` to cause DoS.

**Recommendation:** When `pq_pub` is present, require `algorithm_suite` in the serialized bundle (or default to the hybrid suite and require it to be explicit) so that initiator and responder agree and stripping causes a clear validation error rather than a later handshake failure.

---

## 9. Input Validation & Parsing

### 9.1 Wire Message Parsing

**Finding: Strict.**  
`wire_message_from_dict` requires a dict; a nested `header` dict; `dh`/`n`/`pn` with `_require_int32` (integer, not bool, in [0, 2^32-1]); `ciphertext` and `nonce` as non-empty strings; base64 decoding with error handling; dh length 32, nonce length 12, ciphertext length ≥ 16 (tag). Missing or wrong-type fields raise `InvalidHeaderError`.

### 9.2 Type Safety

**Finding: Good.**  
Counters (n, pn, Ns, Nr, PN, session_version) reject bool and non-integer types in both wire and session parsing. Base64 fields are required to be strings before decode.

### 9.3 Base64 Handling

**Finding: Correct.**  
URL-safe base64 with padding added where needed. Decode failures raise explicit errors (InvalidHeaderError or CorruptedSessionError). No silent fallback.

### 9.4 Ciphertext Upper Bound

**Finding: Minor gap (low).**  
There is a minimum length (16 bytes) but no maximum. Extremely large ciphertexts could cause high memory use or DoS.

**Recommendation:** Consider a reasonable maximum ciphertext size (e.g. 1 MiB) and reject larger payloads.

---

## 10. Persistence Safety

### 10.1 Corrupted State Handling

**Finding: Correct.**  
`state_from_dict` validates version, root_key presence and length, and uses `_require_str_b64` for all key material (rejecting non-string types). Counters use `_require_counter` (int, not bool, non-negative). `SkippedMessageKeys.from_dict` and `ReceivedIdsStore.from_dict` validate structure and lengths; failures are wrapped in `CorruptedSessionError`. Malformed `received_ids` or invalid `Ns`/`Nr`/`PN`/`session_version` types raise.

### 10.2 Missing Fields

**Finding: Correct.**  
Required fields (e.g. `root_key`) are accessed and raise `CorruptedSessionError` on missing or invalid data. Optional fields (e.g. sending_chain_key) use `.get()` and are validated when present.

### 10.3 Invalid Encodings

**Finding: Correct.**  
Base64 decoding is wrapped; invalid encoding raises. Key lengths (32 bytes for keys, 12 for nonce) are enforced after decode. Skipped key entries require 36-byte index and 32-byte key; otherwise `ValueError` is raised and converted to `CorruptedSessionError` by the caller.

---

## 11. Additional Notes

### 11.1 Message Number Bounds in Stores

**Finding: Low.**  
Wire format constrains `n` to [0, 2^32-1] via `_require_int32`. `SkippedMessageKeys` and `ReceivedIdsStore` encode `n` as 4 bytes big-endian but do not enforce an upper bound on `n` when adding. In practice, `Nr`/`Ns` do not exceed 2^32; enforcing the same range in `SkippedMessageKeys.add` and `ReceivedIdsStore.add` would align with the wire format and avoid theoretical encoding collisions (e.g. n and n + 2^32).

**Recommendation:** In `SkippedMessageKeys.add` and `ReceivedIdsStore.add`, require `0 <= n <= 0xFFFF_FFFF` for consistency and reject otherwise.

### 11.2 PeerBundle.from_dict Robustness

**Finding: Low.**  
Missing top-level or nested fields (e.g. `identity_pub`, `spk["pub"]`) result in `KeyError` or similar. Validation is correct but errors are generic.

**Recommendation:** Add explicit checks for required keys and raise a dedicated error (e.g. `InvalidHeaderError` or `X3DHInitializationError`) with a clear message for better diagnostics and consistent handling.

---

## Summary Table

| Area                    | Severity | Status / Note                                              |
|-------------------------|----------|------------------------------------------------------------|
| AEAD / nonce / key use  | —        | Correct                                                    |
| KDF domain separation   | —        | Correct                                                    |
| Double Ratchet logic    | —        | Correct                                                    |
| Replay (recent messages)| —        | Robust                                                     |
| Replay (evicted IDs)     | Medium   | Bounded window; document or tighten                        |
| AAD canonicalization    | —        | Correct                                                    |
| Anti-rollback           | —        | Correct                                                    |
| Transcript binding      | —        | Correct                                                    |
| X3DH / SPK / OPK        | —        | Correct (verify-only key: low code-quality note)            |
| PQC hybrid              | —        | Correct; require algorithm_suite when pq_pub present (low)  |
| Wire parsing            | —        | Strict; consider max ciphertext size (low)                 |
| Persistence              | —        | Strict; consider n upper bound in stores (low)             |

---

**Conclusion:** The implementation is logically correct, enforces the stated invariants, and fails safely on invalid or tampered data. The main finding is the bounded replay window after eviction of old received IDs (medium; document or refine). The rest are low-severity improvements for consistency, robustness, and clarity. No high-severity vulnerabilities were identified in the audited code.
