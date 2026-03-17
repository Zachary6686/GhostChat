from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from nacl.public import PrivateKey as X25519PrivateKey, PublicKey as X25519PublicKey

from .errors import OneTimePreKeyExhaustedError, InvalidSignatureError
from .identity import IdentityKeyPair
from .serialization import SerializedPreKey


@dataclass(frozen=True)
class SignedPreKey:
    """
    X25519 signed pre-key (SPK), authenticated by the Ed25519 identity key.
    """

    key_id: int
    public_key: bytes
    private_key: bytes
    signature: bytes

    @classmethod
    def generate(cls, key_id: int, identity: IdentityKeyPair) -> "SignedPreKey":
        sk = X25519PrivateKey.generate()
        pk_bytes = bytes(sk.public_key)
        signature = identity.sign(pk_bytes)
        return cls(key_id=key_id, public_key=pk_bytes, private_key=bytes(sk), signature=signature)

    def verify(self, identity: IdentityKeyPair) -> None:
        identity.verify(self.public_key, self.signature)

    def serialize(self, include_private: bool = True) -> SerializedPreKey:
        return SerializedPreKey(
            key_id=self.key_id,
            public_key=self.public_key,
            private_key=self.private_key if include_private else None,
            signature=self.signature,
            kind="spk",
        )

    @classmethod
    def deserialize(cls, data: SerializedPreKey) -> "SignedPreKey":
        if data.kind != "spk":
            raise InvalidSignatureError("Serialized pre-key is not an SPK")
        if data.private_key is None or data.signature is None:
            raise InvalidSignatureError("SPK missing private key or signature")
        return cls(
            key_id=data.key_id,
            public_key=data.public_key,
            private_key=data.private_key,
            signature=data.signature,
        )

    def to_x25519_pair(self) -> Tuple[X25519PrivateKey, X25519PublicKey]:
        sk = X25519PrivateKey(self.private_key)
        return sk, sk.public_key


@dataclass(frozen=True)
class OneTimePreKey:
    """
    X25519 one-time pre-key (OPK).
    """

    key_id: int
    public_key: bytes
    private_key: bytes

    @classmethod
    def generate(cls, key_id: int) -> "OneTimePreKey":
        sk = X25519PrivateKey.generate()
        return cls(key_id=key_id, public_key=bytes(sk.public_key), private_key=bytes(sk))

    def serialize(self, include_private: bool = True) -> SerializedPreKey:
        return SerializedPreKey(
            key_id=self.key_id,
            public_key=self.public_key,
            private_key=self.private_key if include_private else None,
            signature=None,
            kind="opk",
        )

    @classmethod
    def deserialize(cls, data: SerializedPreKey) -> "OneTimePreKey":
        if data.kind != "opk":
            raise OneTimePreKeyExhaustedError("Serialized pre-key is not an OPK")
        if data.private_key is None:
            raise OneTimePreKeyExhaustedError("OPK missing private key")
        return cls(key_id=data.key_id, public_key=data.public_key, private_key=data.private_key)

    def to_x25519_pair(self) -> Tuple[X25519PrivateKey, X25519PublicKey]:
        sk = X25519PrivateKey(self.private_key)
        return sk, sk.public_key


@dataclass
class PreKeyBundle:
    """
    Bundle of identity-bound SPK and a pool of OPKs.

    This is the Phase 1 building block for X3DH-style handshakes.
    """

    identity: IdentityKeyPair
    signed_prekey: SignedPreKey
    one_time_prekeys: Dict[int, OneTimePreKey] = field(default_factory=dict)
    used_one_time_ids: List[int] = field(default_factory=list)

    @classmethod
    def generate(
        cls,
        *,
        identity: Optional[IdentityKeyPair] = None,
        spk_id: int = 1,
        opk_start_id: int = 1000,
        opk_count: int = 10,
    ) -> "PreKeyBundle":
        identity_pair = identity or IdentityKeyPair.generate()
        spk = SignedPreKey.generate(spk_id, identity_pair)
        opks: Dict[int, OneTimePreKey] = {}
        for i in range(opk_count):
            key_id = opk_start_id + i
            opks[key_id] = OneTimePreKey.generate(key_id)
        return cls(identity=identity_pair, signed_prekey=spk, one_time_prekeys=opks)

    def verify_spk(self) -> None:
        self.signed_prekey.verify(self.identity)

    def consume_one_time_prekey(self) -> OneTimePreKey:
        """
        Consume and return a single OPK.

        Raises OneTimePreKeyExhaustedError if none remain.
        """
        if not self.one_time_prekeys:
            raise OneTimePreKeyExhaustedError("No one-time pre-keys available")
        key_id, opk = next(iter(self.one_time_prekeys.items()))
        del self.one_time_prekeys[key_id]
        self.used_one_time_ids.append(key_id)
        return opk

    def peek_one_time_prekey_ids(self) -> List[int]:
        return sorted(self.one_time_prekeys.keys())

    # Serialization helpers for publishing and local storage.

    def serialize_public_bundle(self) -> dict:
        """
        Serialize the public components of the pre-key bundle suitable for publication.
        """
        return {
            "identity_pub": self.identity.serialize().to_dict()["pub"],
            "spk": self.signed_prekey.serialize(include_private=False).to_dict(),
            "opks": [
                opk.serialize(include_private=False).to_dict()
                for opk in sorted(self.one_time_prekeys.values(), key=lambda k: k.key_id)
            ],
        }

