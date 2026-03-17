from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from crypto.hkdf import hkdf_derive


@dataclass(frozen=True)
class RatchetKDFParameters:
    root_info: bytes = b"ghostchat-ratchet-root"
    chain_info: bytes = b"ghostchat-ratchet-chain"
    root_salt: bytes = b"ghostchat-ratchet-root-salt"
    chain_salt: bytes = b"ghostchat-ratchet-chain-salt"
    key_length: int = 32


def kdf_root(root_key: bytes, dh_out: bytes, params: RatchetKDFParameters | None = None) -> tuple[bytes, bytes]:
    """
    Root key KDF: KDF_RK(RK, DH_OUT) -> (RK', CK).
    """

    p = params or RatchetKDFParameters()
    material = hkdf_derive(
        ikm=dh_out,
        salt=root_key or p.root_salt,
        info=p.root_info,
        length=2 * p.key_length,
    )
    return material[: p.key_length], material[p.key_length :]


def kdf_chain(chain_key: bytes, params: RatchetKDFParameters | None = None) -> Tuple[bytes, bytes]:
    """
    Chain key KDF: KDF_CK(CK) -> (CK', MK).
    """

    p = params or RatchetKDFParameters()
    material = hkdf_derive(
        ikm=chain_key,
        salt=p.chain_salt,
        info=p.chain_info,
        length=2 * p.key_length,
    )
    return material[: p.key_length], material[p.key_length :]

