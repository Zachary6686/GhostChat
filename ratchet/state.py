from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from nacl.public import PrivateKey as X25519PrivateKey, PublicKey as X25519PublicKey

from .skipped_keys import SkippedKeyStore


@dataclass
class RatchetHeader:
    """
    Metadata header transmitted with every message.
    """

    dh_pub: bytes
    pn: int  # previous sending chain length
    n: int  # message number in current sending chain


@dataclass
class RatchetState:
    """
    Minimal in-memory state for the double ratchet.
    """

    root_key: bytes
    dhs: X25519PrivateKey  # our current DH ratchet private key
    dhr: Optional[bytes]  # their current DH ratchet public key (bytes)
    ck_s: Optional[bytes]  # sending chain key
    ck_r: Optional[bytes]  # receiving chain key
    Ns: int  # number of messages sent in current sending chain
    Nr: int  # number of messages received in current receiving chain
    PN: int  # number of messages sent in previous sending chain
    skipped_keys: SkippedKeyStore

    @property
    def dhs_public_bytes(self) -> bytes:
        return bytes(self.dhs.public_key)

    def dhr_public(self) -> Optional[X25519PublicKey]:
        return X25519PublicKey(self.dhr) if self.dhr is not None else None

