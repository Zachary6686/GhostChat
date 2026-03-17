from __future__ import annotations

from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


DEFAULT_HKDF_HASH: Final = hashes.SHA256


def hkdf_derive(
    *,
    ikm: bytes,
    salt: bytes,
    info: bytes,
    length: int = 32,
) -> bytes:
    """
    Derive a fixed-length key from input keying material using HKDF-SHA256.

    This is the only HKDF entry point used by GhostChat, to keep key
    derivation auditable and consistent across protocol layers.
    """

    hkdf = HKDF(
        algorithm=DEFAULT_HKDF_HASH(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)

