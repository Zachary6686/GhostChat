from __future__ import annotations

"""
Hybrid X3DH-style handshake building block for GhostChat.

This module implements the *classical* X25519-based shared secret agreement
and provides hooks for an optional PQ KEM backend. It intentionally keeps the
API narrow and focused on deriving a root key suitable for feeding into the
double ratchet.
"""

from dataclasses import dataclass
from typing import Optional, Tuple

from nacl.public import PrivateKey as X25519PrivateKey, PublicKey as X25519PublicKey, Box

from .hkdf import hkdf_derive
from .pqc import PQKEMBackend
from .prekeys import OneTimePreKey, SignedPreKey


@dataclass(frozen=True)
class X3DHParameters:
    """
    Tunable parameters for the X3DH-style KDF.
    """

    info: bytes = b"ghostchat-x3dh-root"
    salt: bytes = b"ghostchat-x3dh-salt"
    key_length: int = 32


@dataclass(frozen=True)
class X3DHSessionSecrets:
    """
    Result of a (hybrid) X3DH-style handshake.
    """

    root_key: bytes
    classical_secret: bytes
    pq_secret: Optional[bytes]


def _dh(a_priv: X25519PrivateKey, b_pub: X25519PublicKey) -> bytes:
    # PyNaCl's Box uses X25519 under the hood and exposes the shared key as
    # a bytes attribute `_shared_key`. This is private API but still rooted
    # in libsodium's X25519 implementation, which is acceptable for this
    # prototype. The value is a 32-byte shared secret suitable to feed into
    # a KDF.
    box = Box(a_priv, b_pub)
    return box._shared_key


def _compute_classical_secret_initiator(
    *,
    eph_priv: X25519PrivateKey,
    responder_spk_pub: bytes,
    responder_opk_pub: Optional[bytes],
) -> bytes:
    spk_pub = X25519PublicKey(responder_spk_pub)
    dh1 = _dh(eph_priv, spk_pub)

    if responder_opk_pub is not None:
        opk_pub = X25519PublicKey(responder_opk_pub)
        dh2 = _dh(eph_priv, opk_pub)
        return dh1 + dh2
    return dh1


def _compute_classical_secret_responder(
    *,
    eph_pub: bytes,
    responder_spk_priv: X25519PrivateKey,
    responder_opk_priv: Optional[X25519PrivateKey],
) -> bytes:
    eph_public = X25519PublicKey(eph_pub)
    dh1 = _dh(responder_spk_priv, eph_public)

    if responder_opk_priv is not None:
        dh2 = _dh(responder_opk_priv, eph_public)
        return dh1 + dh2
    return dh1


def _derive_root_key(
    *,
    classical_secret: bytes,
    pq_secret: Optional[bytes],
    params: X3DHParameters,
) -> bytes:
    if pq_secret is not None:
        ikm = classical_secret + pq_secret
    else:
        ikm = classical_secret
    return hkdf_derive(ikm=ikm, salt=params.salt, info=params.info, length=params.key_length)


def perform_classical_x3dh_handshake(
    *,
    responder_spk: SignedPreKey,
    responder_opk: Optional[OneTimePreKey],
    params: Optional[X3DHParameters] = None,
) -> Tuple[X3DHSessionSecrets, X3DHSessionSecrets, bytes]:
    """
    Perform a classical (non-PQ) X3DH-style handshake.

    Returns (initiator_secrets, responder_secrets, eph_public_bytes).
    """

    params = params or X3DHParameters()

    eph_priv = X25519PrivateKey.generate()
    eph_pub_bytes = bytes(eph_priv.public_key)

    opk_pub_bytes: Optional[bytes] = responder_opk.public_key if responder_opk else None

    classical_init = _compute_classical_secret_initiator(
        eph_priv=eph_priv,
        responder_spk_pub=responder_spk.public_key,
        responder_opk_pub=opk_pub_bytes,
    )

    spk_priv = X25519PrivateKey(responder_spk.private_key)
    opk_priv_x25519: Optional[X25519PrivateKey] = (
        X25519PrivateKey(responder_opk.private_key) if responder_opk else None
    )

    classical_resp = _compute_classical_secret_responder(
        eph_pub=eph_pub_bytes,
        responder_spk_priv=spk_priv,
        responder_opk_priv=opk_priv_x25519,
    )

    assert classical_init == classical_resp

    root_key = _derive_root_key(classical_secret=classical_init, pq_secret=None, params=params)
    secrets_init = X3DHSessionSecrets(root_key=root_key, classical_secret=classical_init, pq_secret=None)
    secrets_resp = X3DHSessionSecrets(root_key=root_key, classical_secret=classical_resp, pq_secret=None)
    return secrets_init, secrets_resp, eph_pub_bytes


def perform_hybrid_x3dh_handshake(
    *,
    responder_spk: SignedPreKey,
    responder_opk: Optional[OneTimePreKey],
    pq_backend: PQKEMBackend,
    params: Optional[X3DHParameters] = None,
) -> Tuple[X3DHSessionSecrets, X3DHSessionSecrets, bytes, bytes]:
    """
    Perform a hybrid X3DH-style handshake using a classical X25519 component
    and an additional PQ KEM shared secret.

    Returns (initiator_secrets, responder_secrets, eph_public_bytes, pq_ciphertext).

    The caller is responsible for transporting `eph_public_bytes` and
    `pq_ciphertext` from initiator to responder in a higher-level protocol
    message.
    """

    params = params or X3DHParameters()

    # Classical part.
    eph_priv = X25519PrivateKey.generate()
    eph_pub_bytes = bytes(eph_priv.public_key)
    opk_pub_bytes: Optional[bytes] = responder_opk.public_key if responder_opk else None

    classical_init = _compute_classical_secret_initiator(
        eph_priv=eph_priv,
        responder_spk_pub=responder_spk.public_key,
        responder_opk_pub=opk_pub_bytes,
    )

    spk_priv = X25519PrivateKey(responder_spk.private_key)
    opk_priv_x25519: Optional[X25519PrivateKey] = (
        X25519PrivateKey(responder_opk.private_key) if responder_opk else None
    )

    classical_resp = _compute_classical_secret_responder(
        eph_pub=eph_pub_bytes,
        responder_spk_priv=spk_priv,
        responder_opk_priv=opk_priv_x25519,
    )

    assert classical_init == classical_resp

    # PQ part: responder generates PQ key pair; initiator encapsulates.
    pq_pub, pq_sk = pq_backend.generate_keypair()
    pq_ct, pq_secret_init = pq_backend.encapsulate(pq_pub)
    pq_secret_resp = pq_backend.decapsulate(pq_ct, pq_sk)

    assert pq_secret_init == pq_secret_resp

    root_init = _derive_root_key(
        classical_secret=classical_init,
        pq_secret=pq_secret_init,
        params=params,
    )
    root_resp = _derive_root_key(
        classical_secret=classical_resp,
        pq_secret=pq_secret_resp,
        params=params,
    )

    secrets_init = X3DHSessionSecrets(
        root_key=root_init,
        classical_secret=classical_init,
        pq_secret=pq_secret_init,
    )
    secrets_resp = X3DHSessionSecrets(
        root_key=root_resp,
        classical_secret=classical_resp,
        pq_secret=pq_secret_resp,
    )

    return secrets_init, secrets_resp, eph_pub_bytes, pq_ct

