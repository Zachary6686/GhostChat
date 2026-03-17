from __future__ import annotations

from dataclasses import dataclass

from nacl import signing
from nacl.exceptions import BadSignatureError

from .errors import InvalidSignatureError
from .serialization import SerializedIdentity


@dataclass(frozen=True)
class IdentityKeyPair:
    """
    Ed25519 identity key pair.

    The public key acts as the stable account identifier for a GhostChat client.
    """

    public_key: bytes
    private_key: bytes

    @classmethod
    def generate(cls) -> "IdentityKeyPair":
        sk = signing.SigningKey.generate()
        vk = sk.verify_key
        return cls(public_key=bytes(vk), private_key=sk.encode())

    @property
    def signing_key(self) -> signing.SigningKey:
        return signing.SigningKey(self.private_key)

    @property
    def verify_key(self) -> signing.VerifyKey:
        return signing.VerifyKey(self.public_key)

    def sign(self, message: bytes) -> bytes:
        return self.signing_key.sign(message).signature

    def verify(self, message: bytes, signature: bytes) -> None:
        try:
            self.verify_key.verify(message, signature)
        except BadSignatureError as exc:
            raise InvalidSignatureError("Invalid identity signature") from exc

    def serialize(self) -> SerializedIdentity:
        return SerializedIdentity(public_key=self.public_key, private_key=self.private_key)

    @classmethod
    def deserialize(cls, data: SerializedIdentity) -> "IdentityKeyPair":
        return cls(public_key=data.public_key, private_key=data.private_key)

