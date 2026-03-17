Threat Model (Phase 1)
======================

This document captures the threat model and security assumptions for **Phase 1** of GhostChat (identity + pre-keys). Later phases will extend this model for the full protocol.

## Assets

- Ed25519 **identity secret keys**.
- X25519 **signed pre-keys (SPK)** secret keys.
- X25519 **one-time pre-key (OPK)** secret keys.
- **Signatures** binding the SPK to the identity key.
- Serialized forms of the above.

## Adversaries

1. **Passive network observer**
   - Can observe public identity keys and published pre-key bundles.
2. **Active man-in-the-middle**
   - Can tamper with or replace published pre-key bundles.
3. **Malicious directory / relay**
   - Can reorder, drop, or substitute key material.
4. **Database / filesystem attacker**
   - Can read local serialized key material if they gain access to the machine.

## Protections in Phase 1

- **Authenticity of signed pre-keys**
  - Each SPK is signed with the identity Ed25519 secret key.
  - A peer can verify that the SPK is bound to the claimed identity public key.
- **OPK one-time semantics**
  - The local pre-key manager enforces one-time consumption of OPKs.
  - This minimizes reuse of DH secrets in later phases.
- **Structured serialization**
  - Key material is serialized in explicit, versioned formats.
  - No use of unsafe generic serialization such as pickle.

## Out of Scope in Phase 1

- **Confidentiality of messages**
  - No messaging or session establishment is implemented yet.
- **Forward secrecy and post-compromise security**
  - These depend on the X3DH-style handshake and double-ratchet (future phases).
- **Metadata protection**
  - No sealed sender envelope or routing is present yet.
- **Database encryption and secure deletion**
  - Client storage is not implemented in Phase 1.

## Assumptions

- The host system’s random number generator is not compromised and provides high-entropy randomness.
- The `pynacl` and `cryptography` libraries are correctly implemented and linked against a secure backend (e.g., libsodium, OpenSSL).
- Identity secret keys and pre-key secrets are stored on disk only in controlled environments (Phase 1 does not yet add encrypted storage).

## Known Limitations (Phase 1)

- **No transport security**: Identity and pre-key material could be served over insecure channels, allowing active substitution.
- **No revocation or key rotation**: Identity keys and pre-keys do not yet have lifecycle policies.
- **No persistent audit trail**: Key usage and rotation events are not logged or monitored.

These limitations are intentional at this stage; later phases add handshake, ratcheting, relay, storage, and more detailed protections.

