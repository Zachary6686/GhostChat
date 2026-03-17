"""
Tests for client X3DH session establishment: initialization, OPK consumption,
SPK verification, transcript binding, and error handling.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nacl.public import PrivateKey as X25519PrivateKey

from client.crypto.prekey import (
    ClientPreKeyBundle,
    PeerBundle,
    generate_prekey_bundle,
    serialize_bundle,
)
from client.crypto.ratchet_errors import (
    AlgorithmSuiteMismatchError,
    OneTimePreKeyReuseError,
    SignedPreKeyVerificationError,
    X3DHInitializationError,
)
from client.crypto.x3dh import x3dh_initiator, x3dh_responder
from crypto.identity import IdentityKeyPair
from crypto.pqc import ALGORITHM_SUITE_CLASSICAL, ALGORITHM_SUITE_HYBRID_KYBER, get_testing_pq_backend


def _make_identity() -> IdentityKeyPair:
    return IdentityKeyPair.generate()


def _make_bundle(opk_count: int = 3) -> ClientPreKeyBundle:
    identity = _make_identity()
    return generate_prekey_bundle(identity, opk_count=opk_count)


def _bundle_to_peer_bundle(bundle: ClientPreKeyBundle) -> PeerBundle:
    d = serialize_bundle(bundle, for_upload=True)
    return PeerBundle.from_dict(d)


def test_x3dh_initiator_responder_agree_on_root_key() -> None:
    """Initiator and responder derive the same root key and transcript hash."""
    alice_bundle = _make_bundle(opk_count=2)
    bob_bundle = _make_bundle(opk_count=2)
    peer_bob = _bundle_to_peer_bundle(bob_bundle)
    opk_id, opk_pub = peer_bob.opks[0]

    eph_priv = X25519PrivateKey.generate()
    result_init, eph_pub = x3dh_initiator(
        alice_bundle.identity_dh_private,
        eph_priv,
        peer_bob,
        opk_id_and_pub=(opk_id, opk_pub),
    )
    result_resp = x3dh_responder(
        bob_bundle,
        alice_bundle.identity_dh_public,
        eph_pub,
        opk_id_used=opk_id,
    )

    assert result_init.root_key == result_resp.root_key
    assert result_init.transcript_hash is not None and result_resp.transcript_hash is not None
    assert result_init.transcript_hash == result_resp.transcript_hash


def test_invalid_initialization_bad_bundle_type() -> None:
    """Non-PeerBundle raises X3DHInitializationError."""
    alice_bundle = _make_bundle()
    eph = X25519PrivateKey.generate()
    with pytest.raises(X3DHInitializationError):
        x3dh_initiator(
            alice_bundle.identity_dh_private, eph, None, None  # type: ignore[arg-type]
        )


def test_invalid_initialization_wrong_key_lengths() -> None:
    """Peer bundle with wrong identity_pub or spk_pub length raises X3DHInitializationError."""
    alice_bundle = _make_bundle()
    bob_bundle = _make_bundle()
    peer_bob = _bundle_to_peer_bundle(bob_bundle)
    eph = X25519PrivateKey.generate()
    id_dh = alice_bundle.identity_dh_private

    short_identity = PeerBundle(
        identity_pub=b"x" * 16,
        identity_dh_pub=peer_bob.identity_dh_pub,
        spk_id=peer_bob.spk_id,
        spk_pub=peer_bob.spk_pub,
        spk_sig=peer_bob.spk_sig,
        opks=peer_bob.opks,
    )
    with pytest.raises(X3DHInitializationError):
        x3dh_initiator(id_dh, eph, short_identity, peer_bob.opks[0] if peer_bob.opks else None)

    bad_sig = PeerBundle(
        identity_pub=peer_bob.identity_pub,
        identity_dh_pub=peer_bob.identity_dh_pub,
        spk_id=peer_bob.spk_id,
        spk_pub=peer_bob.spk_pub,
        spk_sig=b"short",
        opks=peer_bob.opks,
    )
    with pytest.raises((X3DHInitializationError, SignedPreKeyVerificationError)):
        x3dh_initiator(id_dh, eph, bad_sig, peer_bob.opks[0] if peer_bob.opks else None)


def test_opk_reuse_raises() -> None:
    """Consuming the same OPK twice raises OneTimePreKeyReuseError."""
    alice_bundle = _make_bundle(opk_count=2)
    bob_bundle = _make_bundle(opk_count=2)
    peer_bob = _bundle_to_peer_bundle(bob_bundle)
    opk_id, opk_pub = peer_bob.opks[0]
    eph = X25519PrivateKey.generate()

    x3dh_initiator(alice_bundle.identity_dh_private, eph, peer_bob, (opk_id, opk_pub))
    x3dh_responder(
        bob_bundle,
        alice_bundle.identity_dh_public,
        bytes(eph.public_key),
        opk_id_used=opk_id,
    )
    with pytest.raises(OneTimePreKeyReuseError):
        x3dh_responder(
            bob_bundle,
            alice_bundle.identity_dh_public,
            bytes(eph.public_key),
            opk_id_used=opk_id,
        )


def test_opk_not_found_raises() -> None:
    """Using an OPK id that is not in the bundle raises OneTimePreKeyReuseError."""
    alice_bundle = _make_bundle(opk_count=1)
    bob_bundle = _make_bundle(opk_count=1)
    eph = X25519PrivateKey.generate()
    eph_pub = bytes(eph.public_key)
    with pytest.raises(OneTimePreKeyReuseError):
        x3dh_responder(
            bob_bundle,
            alice_bundle.identity_dh_public,
            eph_pub,
            opk_id_used=99999,
        )


def test_spk_signature_failure_raises() -> None:
    """Tampered SPK signature causes SignedPreKeyVerificationError."""
    alice_bundle = _make_bundle()
    bob_bundle = _make_bundle()
    peer_bob = _bundle_to_peer_bundle(bob_bundle)
    tampered_peer = PeerBundle(
        identity_pub=peer_bob.identity_pub,
        identity_dh_pub=peer_bob.identity_dh_pub,
        spk_id=peer_bob.spk_id,
        spk_pub=peer_bob.spk_pub,
        spk_sig=bytes(64),
        opks=peer_bob.opks,
    )
    eph = X25519PrivateKey.generate()
    with pytest.raises(SignedPreKeyVerificationError):
        x3dh_initiator(
            alice_bundle.identity_dh_private,
            eph,
            tampered_peer,
            peer_bob.opks[0] if peer_bob.opks else None,
        )


def test_transcript_mismatch_different_eph_different_root_key() -> None:
    """Initiator and responder must use the same ephemeral public; wrong eph yields different root key."""
    alice_bundle = _make_bundle(opk_count=0)
    bob_bundle = _make_bundle(opk_count=0)
    peer_bob = _bundle_to_peer_bundle(bob_bundle)
    eph = X25519PrivateKey.generate()

    result_init, eph_pub = x3dh_initiator(
        alice_bundle.identity_dh_private, eph, peer_bob, None
    )
    result_resp = x3dh_responder(
        bob_bundle, alice_bundle.identity_dh_public, eph_pub, None
    )
    assert result_init.root_key == result_resp.root_key

    wrong_eph_pub = bytes(X25519PrivateKey.generate().public_key)
    result_resp_wrong = x3dh_responder(
        bob_bundle, alice_bundle.identity_dh_public, wrong_eph_pub, None
    )
    assert result_init.root_key != result_resp_wrong.root_key
    assert result_init.transcript_hash != result_resp_wrong.transcript_hash


def test_transcript_binding_initiator_responder_match() -> None:
    """When handshake is correct, transcript_hash from initiator and responder match."""
    alice_bundle = _make_bundle(opk_count=1)
    bob_bundle = _make_bundle(opk_count=1)
    peer_bob = _bundle_to_peer_bundle(bob_bundle)
    opk_id, opk_pub = peer_bob.opks[0]
    eph = X25519PrivateKey.generate()

    result_init, eph_pub = x3dh_initiator(
        alice_bundle.identity_dh_private, eph, peer_bob, (opk_id, opk_pub)
    )
    result_resp = x3dh_responder(
        bob_bundle, alice_bundle.identity_dh_public, eph_pub, opk_id_used=opk_id
    )

    assert result_init.transcript_hash == result_resp.transcript_hash
    assert len(result_init.transcript_hash or b"") == 32


def test_initiator_invalid_identity_dh_private_length() -> None:
    """Initiator with wrong identity_dh_private length raises X3DHInitializationError."""
    bob_bundle = _make_bundle()
    peer_bob = _bundle_to_peer_bundle(bob_bundle)
    eph = X25519PrivateKey.generate()
    with pytest.raises(X3DHInitializationError):
        x3dh_initiator(b"short", eph, peer_bob, None)


def test_responder_invalid_initiator_key_length() -> None:
    """Responder with wrong initiator key length raises X3DHInitializationError."""
    alice_bundle = _make_bundle()
    bob_bundle = _make_bundle()
    eph_pub = bytes(X25519PrivateKey.generate().public_key)
    with pytest.raises(X3DHInitializationError):
        x3dh_responder(bob_bundle, b"short", eph_pub, None)
    with pytest.raises(X3DHInitializationError):
        x3dh_responder(bob_bundle, alice_bundle.identity_dh_public, b"short", None)


# --- PQC hybrid handshake and downgrade/mismatch rejection ---


def _make_hybrid_bundle(opk_count: int = 2) -> ClientPreKeyBundle:
    identity = _make_identity()
    pq = get_testing_pq_backend()
    return generate_prekey_bundle(identity, opk_count=opk_count, pq_backend=pq)


def test_hybrid_handshake_initiator_responder_agree_on_root_key() -> None:
    """Hybrid (X25519 + KEM) handshake: initiator and responder derive the same root key."""
    alice_bundle = _make_bundle(opk_count=2)
    bob_bundle = _make_hybrid_bundle(opk_count=2)
    peer_bob = _bundle_to_peer_bundle(bob_bundle)
    assert peer_bob.pq_pub is not None
    assert peer_bob.algorithm_suite == ALGORITHM_SUITE_HYBRID_KYBER

    opk_id, opk_pub = peer_bob.opks[0]
    pq = get_testing_pq_backend()
    eph = X25519PrivateKey.generate()

    result_init, eph_pub = x3dh_initiator(
        alice_bundle.identity_dh_private,
        eph,
        peer_bob,
        opk_id_and_pub=(opk_id, opk_pub),
        pq_backend=pq,
    )
    assert result_init.pq_ciphertext is not None
    assert result_init.algorithm_suite == ALGORITHM_SUITE_HYBRID_KYBER

    result_resp = x3dh_responder(
        bob_bundle,
        alice_bundle.identity_dh_public,
        eph_pub,
        opk_id_used=opk_id,
        pq_ciphertext=result_init.pq_ciphertext,
        algorithm_suite=result_init.algorithm_suite,
        pq_backend=pq,
    )
    assert result_init.root_key == result_resp.root_key
    assert result_init.transcript_hash == result_resp.transcript_hash


def test_downgrade_rejected_responder_hybrid_but_no_pq_ciphertext() -> None:
    """Responder has hybrid bundle but initiator sends no PQ ciphertext -> AlgorithmSuiteMismatchError."""
    alice_bundle = _make_bundle(opk_count=1)
    bob_bundle = _make_hybrid_bundle(opk_count=1)
    peer_bob = _bundle_to_peer_bundle(bob_bundle)
    opk_id, opk_pub = peer_bob.opks[0]
    eph = X25519PrivateKey.generate()
    pq = get_testing_pq_backend()

    result_init, eph_pub = x3dh_initiator(
        alice_bundle.identity_dh_private,
        eph,
        peer_bob,
        (opk_id, opk_pub),
        pq_backend=pq,
    )
    assert result_init.pq_ciphertext is not None

    with pytest.raises(AlgorithmSuiteMismatchError):
        x3dh_responder(
            bob_bundle,
            alice_bundle.identity_dh_public,
            eph_pub,
            opk_id_used=opk_id,
            pq_ciphertext=None,
            algorithm_suite=ALGORITHM_SUITE_CLASSICAL,
            pq_backend=pq,
        )


def test_mismatch_rejected_initiator_sends_hybrid_responder_classical() -> None:
    """Responder has classical bundle but initiator sends PQ ciphertext / hybrid suite -> AlgorithmSuiteMismatchError."""
    alice_bundle = _make_bundle(opk_count=1)
    bob_bundle = _make_bundle(opk_count=1)
    peer_bob = _bundle_to_peer_bundle(bob_bundle)
    assert peer_bob.pq_pub is None
    opk_id, opk_pub = peer_bob.opks[0]
    eph = X25519PrivateKey.generate()

    with pytest.raises(AlgorithmSuiteMismatchError):
        x3dh_responder(
            bob_bundle,
            alice_bundle.identity_dh_public,
            bytes(eph.public_key),
            opk_id_used=opk_id,
            pq_ciphertext=b"fake-pq-ct",
            algorithm_suite=ALGORITHM_SUITE_HYBRID_KYBER,
        )


def test_peer_bundle_hybrid_without_pq_backend_raises() -> None:
    """Initiator with hybrid peer bundle but no pq_backend raises AlgorithmSuiteMismatchError."""
    alice_bundle = _make_bundle(opk_count=1)
    bob_bundle = _make_hybrid_bundle(opk_count=1)
    peer_bob = _bundle_to_peer_bundle(bob_bundle)
    opk_id, opk_pub = peer_bob.opks[0]
    eph = X25519PrivateKey.generate()

    with pytest.raises(AlgorithmSuiteMismatchError):
        x3dh_initiator(
            alice_bundle.identity_dh_private,
            eph,
            peer_bob,
            opk_id_and_pub=(opk_id, opk_pub),
            pq_backend=None,
        )


def test_classical_only_backward_compatible_no_pq() -> None:
    """Classical-only mode: no PQ in bundle, no pq_backend; same behavior as before hybrid was added."""
    alice_bundle = _make_bundle(opk_count=1)
    bob_bundle = _make_bundle(opk_count=1)
    peer_bob = _bundle_to_peer_bundle(bob_bundle)
    opk_id, opk_pub = peer_bob.opks[0]
    eph = X25519PrivateKey.generate()

    result_init, eph_pub = x3dh_initiator(
        alice_bundle.identity_dh_private, eph, peer_bob, (opk_id, opk_pub)
    )
    result_resp = x3dh_responder(
        bob_bundle, alice_bundle.identity_dh_public, eph_pub, opk_id_used=opk_id
    )
    assert result_init.root_key == result_resp.root_key
    assert result_init.pq_ciphertext is None
    assert result_init.algorithm_suite == ALGORITHM_SUITE_CLASSICAL
