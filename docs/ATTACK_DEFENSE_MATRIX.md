# Attack–Defense Matrix

Single matrix: **Attack / Failure case** → **Defense mechanism** → **Residual risk**. Suitable for security review and portfolio presentation.

| Attack / Failure case | Defense mechanism | Residual risk |
|----------------------|-------------------|---------------|
| MITM during session establishment | SPK signed by IK and verified; X3DH binds shared secret to verified bundle | Malicious directory can substitute bundle; no TOFU/pinning in prototype |
| Forged signed prekey | `SignedPreKey.verify(identity)`; handshake uses only verified bundle | Same as above; trust in prekey distribution channel |
| Replayed one-to-one message | `SessionReplayCache` (sid, rk, n); reject before ratchet decrypt; `mark_for_reset` | Replay can force session reset (DoS); no cross-device binding |
| Malformed protocol envelope | `ProtocolEnvelope.from_dict` / `SealedOuterEnvelope.from_dict` validate version and required fields; raise on invalid | Parsing edge cases; no fuzzing in prototype |
| Forked / inconsistent ratchet progression | `detect_fork()` before decrypt; `mark_for_reset()`; no blind decryption after fork | Fork can force reset (DoS); heuristic only |
| Malicious relay reading payload | Relay has no decryption; payload in sealed envelope (opaque to relay) | Device/endpoint compromise; size/timing observable |
| Relay learning sender identity (sealed sender mode) | Outer envelope has only `recipient_locator`, `ttl`, `sp`, `pad`; `get_routing_recipient` uses recipient only | Recipient/mailbox IDs visible; timing/size correlation possible |
| Timing correlation on traffic | Mix delays, jitter, batching; cover and dummy traffic | Best-effort; strong traffic analysis still possible |
| Dummy / cover traffic misuse | Same outer shape as real; recipient drops undecryptable without updating session state | Real message dropped if misclassified (e.g. wrong session); no padding normalization |
| Stale group epoch injection | `GroupMessenger.decrypt` rejects `header.epoch != state.epoch`; `EpochMismatchError` | App must fetch latest state; no automatic push |
| Removed member attempting future decryption | Leaf overwrite + tree recompute + new GK/AK per epoch; removed member not given new state | Requires timely propagation of updated GroupState; single coordinator trusted |
| New member attempting past decryption | New members receive state only for join epoch; epoch check rejects older messages | Same as above |
| Group state divergence | Group hash + epoch; `verify_consistency`; no silent acceptance of divergent state | Malicious coordinator can push consistent but attacker-chosen state |
| Local encrypted storage theft | Encrypted DB; no plaintext session keys in long-term storage; FS/PCS from ratchet | If storage key compromised, all local state readable; no secure deletion guarantee |
| Relay restart / ephemeral mailbox loss | RAM-only mailbox by design; TTL and drop on restart | Messages in queue at restart lost; no guaranteed delivery |
| Denial-of-service via malformed traffic | Envelope validation raises; no silent accept; bounded caches and TTLs | Flooding and repeated resets can still cause DoS; no rate limiting in prototype |

## Summary

- **Strong defenses:** E2E encryption (X3DH + double ratchet); SPK verification; replay/fork detection and reset; payload-blind relay; sealed sender outer envelope; group epoch and replay checks; encrypted storage design.
- **Best-effort:** Mix/cover/dummy and timing; DoS mitigated by bounds and TTLs only.
- **Out of scope:** Strong anonymity; protection against full device/OS compromise.
