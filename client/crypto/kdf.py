"""
Key derivation for Double Ratchet (client).

HKDF-SHA256 based: root key update, chain key evolution, message key derivation.
"""

from __future__ import annotations

from typing import Tuple

from crypto.hkdf import hkdf_derive

ROOT_INFO = b"ghostchat-ratchet-root"
ROOT_SALT = b"ghostchat-ratchet-root-salt"
CHAIN_INFO = b"ghostchat-ratchet-chain"
CHAIN_SALT = b"ghostchat-ratchet-chain-salt"
KEY_LENGTH = 32


def kdf_root(root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
    """
    Root key KDF: KDF_RK(RK, DH_OUT) -> (RK', CK).
    Returns (new_root_key, chain_key).
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
    Chain key KDF: KDF_CK(CK) -> (CK', MK).
    Returns (new_chain_key, message_key).
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
    """Derive initial sending chain key (initiator) or receiving (responder) from root key."""
    return hkdf_derive(ikm=root_key, salt=ROOT_SALT, info=FIRST_SEND_INFO, length=KEY_LENGTH)
