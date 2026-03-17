"""
Full X3DH key agreement for GhostChat client.

- First-message initialization checks; stronger signed prekey verification.
- One-time prekey atomic consumption (responder).
- Session transcript binding (root key bound to handshake transcript).
- Non-sensitive audit logging.
"""

from __future__ import annotations

import hashlib
import logging
import struct
from dataclasses import dataclass
from typing import Any, Optional, Tuple

from nacl.public import Box, PrivateKey as X25519PrivateKey, PublicKey as X25519PublicKey
from nacl.signing import VerifyKey

from crypto.hkdf import hkdf_derive
from crypto.identity import IdentityKeyPair

from client.crypto.hybrid import combine_shared_secrets, is_hybrid_suite
from client.crypto.prekey import ClientPreKeyBundle, PeerBundle
from client.crypto.ratchet_errors import (
    AlgorithmSuiteMismatchError,
    OneTimePreKeyReuseError,
    SignedPreKeyVerificationError,
    X3DHInitializationError,
)
from crypto.pqc import ALGORITHM_SUITE_CLASSICAL, ALGORITHM_SUITE_HYBRID_KYBER

AUDIT = logging.getLogger("ghostchat.x3dh.audit")
KEY_LEN = 32
ED25519_SIG_LEN = 64

X3DH_SALT = b"ghostchat-x3dh-v1"
X3DH_INFO = b"ghostchat-x3dh-shared"
X3DH_ROOT_INFO = b"ghostchat-x3dh-root"
X3DH_ROOT_SALT = b"ghostchat-x3dh-root-salt"


def _dh(priv: X25519PrivateKey, pub: X25519PublicKey) -> bytes:
    box = Box(priv, pub)
    return box._shared_key


def _validate_peer_bundle(peer_bundle: PeerBundle) -> None:
    if not isinstance(peer_bundle, PeerBundle):
        raise X3DHInitializationError("Peer bundle must be a PeerBundle instance")
    if len(peer_bundle.identity_pub) != KEY_LEN:
        raise X3DHInitializationError("Invalid identity_pub length")
    if len(peer_bundle.identity_dh_pub) != KEY_LEN:
        raise X3DHInitializationError("Invalid identity_dh_pub length")
    if len(peer_bundle.spk_pub) != KEY_LEN:
        raise X3DHInitializationError("Invalid spk_pub length")
    if not peer_bundle.spk_sig or len(peer_bundle.spk_sig) != ED25519_SIG_LEN:
        raise X3DHInitializationError("Invalid or missing SPK signature (expected 64 bytes)")
    for opk_id, opk_pub in peer_bundle.opks:
        if len(opk_pub) != KEY_LEN:
            raise X3DHInitializationError("Invalid OPK public key length")
        if not isinstance(opk_id, int) or opk_id < 0:
            raise X3DHInitializationError("Invalid OPK key id")


def _verify_spk_signature(identity_pub: bytes, spk_pub: bytes, spk_sig: bytes) -> None:
    if len(identity_pub) != KEY_LEN or len(spk_pub) != KEY_LEN or len(spk_sig) != ED25519_SIG_LEN:
        raise SignedPreKeyVerificationError("SPK or identity key or signature length invalid")
    try:
        vk = VerifyKey(identity_pub)
        vk.verify(spk_pub, spk_sig)
    except Exception as e:
        raise SignedPreKeyVerificationError("Signed prekey signature verification failed") from e


def _build_transcript(
    ik_a_pub: bytes,
    ik_b_pub: bytes,
    spk_b_pub: bytes,
    eph_pub: bytes,
    opk_id: Optional[int],
    algorithm_suite: bytes,
) -> bytes:
    """Build canonical transcript; include algorithm_suite only for hybrid (downgrade detection)."""
    opk_id_bytes = struct.pack(">I", opk_id if opk_id is not None else 0xFFFF_FFFF)
    base = ik_a_pub + ik_b_pub + spk_b_pub + eph_pub + opk_id_bytes
    if algorithm_suite != ALGORITHM_SUITE_CLASSICAL:
        return base + algorithm_suite
    return base


def _transcript_hash(transcript: bytes) -> bytes:
    return hashlib.sha256(transcript).digest()


@dataclass
class X3DHResult:
    """Result of X3DH: root key, optional OPK id, transcript hash, and for hybrid: pq_ciphertext and algorithm_suite."""

    root_key: bytes
    used_opk_id: Optional[int] = None
    transcript_hash: Optional[bytes] = None
    pq_ciphertext: Optional[bytes] = None
    algorithm_suite: bytes = ALGORITHM_SUITE_CLASSICAL


def x3dh_initiator(
    identity_dh_private: bytes,
    ephemeral_private: X25519PrivateKey,
    peer_bundle: PeerBundle,
    opk_id_and_pub: Optional[Tuple[int, bytes]] = None,
    pq_backend: Optional[Any] = None,
) -> Tuple[X3DHResult, bytes]:
    """
    Run X3DH as initiator. Validate bundle, verify SPK, compute DH1–DH4.
    If peer bundle has PQ and pq_backend is provided, perform hybrid (X25519 + KEM) with domain separation.
    Root key is bound to transcript including algorithm suite. Backward compatible: no pq_backend => classical only.
    """
    AUDIT.info("X3DH initiator started")
    _validate_peer_bundle(peer_bundle)
    _verify_spk_signature(peer_bundle.identity_pub, peer_bundle.spk_pub, peer_bundle.spk_sig)
    if len(identity_dh_private) != KEY_LEN:
        raise X3DHInitializationError("Invalid identity_dh_private length")

    if peer_bundle.pq_pub is not None and is_hybrid_suite(peer_bundle.algorithm_suite):
        if pq_backend is None:
            raise AlgorithmSuiteMismatchError("Peer bundle is hybrid but no PQ backend provided")

    ik_a = X25519PrivateKey(identity_dh_private)
    ik_a_pub = bytes(ik_a.public_key)
    spk_b_pub = X25519PublicKey(peer_bundle.spk_pub)
    ik_b_pub = X25519PublicKey(peer_bundle.identity_dh_pub)

    dh1 = _dh(ik_a, spk_b_pub)
    dh2 = _dh(ephemeral_private, ik_b_pub)
    dh3 = _dh(ephemeral_private, spk_b_pub)

    if opk_id_and_pub is not None:
        opk_id, opk_pub = opk_id_and_pub
        if len(opk_pub) != KEY_LEN:
            raise X3DHInitializationError("Invalid OPK public key length")
        opk_b_pub = X25519PublicKey(opk_pub)
        dh4 = _dh(ephemeral_private, opk_b_pub)
        ikm = dh1 + dh2 + dh3 + dh4
        used_opk_id: Optional[int] = opk_id
    else:
        ikm = dh1 + dh2 + dh3
        used_opk_id = None

    shared_x3dh = hkdf_derive(ikm=ikm, salt=X3DH_SALT, info=X3DH_INFO, length=32)
    pq_ct = None
    pq_shared = None
    algorithm_suite = ALGORITHM_SUITE_CLASSICAL
    if (
        peer_bundle.pq_pub is not None
        and is_hybrid_suite(peer_bundle.algorithm_suite)
        and pq_backend is not None
    ):
        pq_ct, pq_shared = pq_backend.encapsulate(peer_bundle.pq_pub)
        algorithm_suite = peer_bundle.algorithm_suite

    eph_pub_bytes = bytes(ephemeral_private.public_key)
    transcript = _build_transcript(
        ik_a_pub, peer_bundle.identity_dh_pub, peer_bundle.spk_pub, eph_pub_bytes, used_opk_id, algorithm_suite
    )
    th = _transcript_hash(transcript)
    if algorithm_suite == ALGORITHM_SUITE_CLASSICAL:
        root_key = hkdf_derive(ikm=shared_x3dh, salt=X3DH_ROOT_SALT, info=X3DH_ROOT_INFO + th, length=32)
    else:
        combined = combine_shared_secrets(shared_x3dh, pq_shared, algorithm_suite)
        root_key = hkdf_derive(
            ikm=combined,
            salt=X3DH_ROOT_SALT,
            info=X3DH_ROOT_INFO + th + algorithm_suite,
            length=32,
        )
    AUDIT.info("X3DH initiator completed")
    return (
        X3DHResult(
            root_key=root_key,
            used_opk_id=used_opk_id,
            transcript_hash=th,
            pq_ciphertext=pq_ct,
            algorithm_suite=algorithm_suite,
        ),
        eph_pub_bytes,
    )


def x3dh_responder(
    bundle: ClientPreKeyBundle,
    initiator_identity_dh_pub: bytes,
    initiator_eph_pub: bytes,
    opk_id_used: Optional[int] = None,
    pq_ciphertext: Optional[bytes] = None,
    algorithm_suite: Optional[bytes] = None,
    pq_backend: Optional[Any] = None,
) -> X3DHResult:
    """
    Complete X3DH as responder. SPK verified; OPK consumed atomically.
    If bundle has PQ keys and suite is hybrid, pq_ciphertext is required; else must be absent (downgrade/mismatch rejection).
    """
    AUDIT.info("X3DH responder started")
    if len(initiator_identity_dh_pub) != KEY_LEN or len(initiator_eph_pub) != KEY_LEN:
        raise X3DHInitializationError("Invalid initiator key length")

    suite = algorithm_suite if algorithm_suite is not None else ALGORITHM_SUITE_CLASSICAL
    bundle_has_pq = bundle.pq_secret_key is not None and bundle.pq_public_key is not None
    bundle_is_hybrid = bundle_has_pq and is_hybrid_suite(bundle.algorithm_suite)

    if bundle_is_hybrid and (pq_ciphertext is None or not is_hybrid_suite(suite)):
        raise AlgorithmSuiteMismatchError("Responder bundle is hybrid but initiator did not send PQ ciphertext or suite mismatch")
    if not bundle_is_hybrid and (pq_ciphertext is not None or is_hybrid_suite(suite)):
        raise AlgorithmSuiteMismatchError("Responder bundle is classical but initiator sent PQ material or hybrid suite")

    bundle.verify_spk()

    spk_b_priv = X25519PrivateKey(bundle.signed_prekey.private_key)
    ik_b_priv = X25519PrivateKey(bundle.identity_dh_private)
    ik_a_pub = X25519PublicKey(initiator_identity_dh_pub)
    eph_a_pub = X25519PublicKey(initiator_eph_pub)
    ik_b_pub = bytes(ik_b_priv.public_key)
    spk_b_pub = bytes(bundle.signed_prekey.public_key)

    dh1 = _dh(spk_b_priv, ik_a_pub)
    dh2 = _dh(ik_b_priv, eph_a_pub)
    dh3 = _dh(spk_b_priv, eph_a_pub)

    if opk_id_used is not None:
        opk = bundle.consume_one_time_prekey(opk_id_used)
        opk_priv = X25519PrivateKey(opk.private_key)
        dh4 = _dh(opk_priv, eph_a_pub)
        ikm = dh1 + dh2 + dh3 + dh4
        used_opk_id: Optional[int] = opk_id_used
    else:
        ikm = dh1 + dh2 + dh3
        used_opk_id = None

    shared_x3dh = hkdf_derive(ikm=ikm, salt=X3DH_SALT, info=X3DH_INFO, length=32)
    pq_shared_val: Optional[bytes] = None
    if bundle_is_hybrid and pq_ciphertext is not None and bundle.pq_secret_key is not None:
        if pq_backend is None:
            raise AlgorithmSuiteMismatchError("Responder bundle is hybrid but no PQ backend provided for decapsulation")
        if len(pq_ciphertext) == 0:
            raise X3DHInitializationError("PQ ciphertext empty (malformed or truncated)")
        pq_shared_val = pq_backend.decapsulate(pq_ciphertext, bundle.pq_secret_key)
    # else: classical or no PQ material -> pq_shared_val stays None

    transcript = _build_transcript(
        initiator_identity_dh_pub, ik_b_pub, spk_b_pub, initiator_eph_pub, used_opk_id, suite
    )
    th = _transcript_hash(transcript)
    if suite == ALGORITHM_SUITE_CLASSICAL:
        root_key = hkdf_derive(ikm=shared_x3dh, salt=X3DH_ROOT_SALT, info=X3DH_ROOT_INFO + th, length=32)
    else:
        combined = combine_shared_secrets(shared_x3dh, pq_shared_val, suite)
        root_key = hkdf_derive(
            ikm=combined,
            salt=X3DH_ROOT_SALT,
            info=X3DH_ROOT_INFO + th + suite,
            length=32,
        )
    AUDIT.info("X3DH responder completed")
    return X3DHResult(
        root_key=root_key,
        used_opk_id=used_opk_id,
        transcript_hash=th,
        pq_ciphertext=None,
        algorithm_suite=suite,
    )
