"""
Key derivation for Double Ratchet (client).

HKDF-SHA256 with strict domain separation: root, chain, and initial-chain use
distinct (salt, info). No accidental reuse of inputs across contexts.
"""

from __future__ import annotations

from typing import Tuple

from crypto.hkdf import hkdf_derive

# Domain separation: each context has unique salt and info.
ROOT_INFO = b"ghostchat-ratchet-root"
ROOT_SALT = b"ghostchat-ratchet-root-salt"
CHAIN_INFO = b"ghostchat-ratchet-chain"
CHAIN_SALT = b"ghostchat-ratchet-chain-salt"
KEY_LENGTH = 32


def kdf_root(root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
    """
    Root key KDF: KDF_RK(RK, DH_OUT) -> (RK', CK). Domain-separated from chain KDF.
    Returns (new_root_key, chain_key). Do not use output as nonce or for other contexts.
    """
    material = hkdf_derive(
        ikm=dh_output,
        salt=root_key or ROOT_SALT,
        info=ROOT_INFO,
        length=2 * KEY_LENGTH,
    )
    return material[:KEY_LENGTH], material[KEY_LENGTH:]


def kdf_chain(chain_key: bytes) -> Tuple[bytes, bytes]:
    """
    Chain key KDF: KDF_CK(CK) -> (CK', MK). One message key per call; no reuse.
    Returns (new_chain_key, message_key). Message key must be used for a single AEAD operation.
    """
    material = hkdf_derive(
        ikm=chain_key,
        salt=CHAIN_SALT,
        info=CHAIN_INFO,
        length=2 * KEY_LENGTH,
    )
    return material[:KEY_LENGTH], material[KEY_LENGTH:]


FIRST_SEND_INFO = b"ghostchat-dr-first-send"


def kdf_initial_chain(root_key: bytes) -> bytes:
    """Derive initial sending/receiving chain key from root key. Domain-separated (FIRST_SEND_INFO)."""
    return hkdf_derive(ikm=root_key, salt=ROOT_SALT, info=FIRST_SEND_INFO, length=KEY_LENGTH)
