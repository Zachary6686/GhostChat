from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import ClassVar

from .errors import InvalidKeyFormatError


def b64u_encode(data: bytes) -> str:
    """URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(data: str) -> bytes:
    """URL-safe base64 without padding."""
    padding = "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode((data + padding).encode("ascii"))
    except Exception as exc:  # pragma: no cover - defensive
        raise InvalidKeyFormatError("Invalid base64-url data") from exc


@dataclass(frozen=True)
class SerializedIdentity:
    """
    Versioned container for an identity key pair.

    Format (JSON-serializable dict when using .to_dict()):
        {
            "v": 1,
            "pub": "<b64u>",
            "priv": "<b64u>",
        }
    """

    version: ClassVar[int] = 1
    public_key: bytes
    private_key: bytes

    def to_dict(self) -> dict:
        return {
            "v": self.version,
            "pub": b64u_encode(self.public_key),
            "priv": b64u_encode(self.private_key),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SerializedIdentity":
        if data.get("v") != cls.version:
            raise InvalidKeyFormatError("Unsupported identity serialization version")
        try:
            pub = b64u_decode(data["pub"])
            priv = b64u_decode(data["priv"])
        except KeyError as exc:
            raise InvalidKeyFormatError("Missing identity fields") from exc
        return cls(public_key=pub, private_key=priv)


@dataclass(frozen=True)
class SerializedPreKey:
    """
    Versioned container for a pre-key (SPK or OPK).

    Format:
        {
            "v": 1,
            "id": <int>,
            "pub": "<b64u>",
            "priv": "<b64u>" | null,
            "sig": "<b64u>" | null,  # only for SPK
            "type": "spk" | "opk",
        }
    """

    version: ClassVar[int] = 1
    key_id: int
    public_key: bytes
    private_key: bytes | None
    signature: bytes | None
    kind: str  # "spk" or "opk"

    def to_dict(self) -> dict:
        return {
            "v": self.version,
            "id": self.key_id,
            "pub": b64u_encode(self.public_key),
            "priv": b64u_encode(self.private_key) if self.private_key is not None else None,
            "sig": b64u_encode(self.signature) if self.signature is not None else None,
            "type": self.kind,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SerializedPreKey":
        if data.get("v") != cls.version:
            raise InvalidKeyFormatError("Unsupported pre-key serialization version")
        if data.get("type") not in {"spk", "opk"}:
            raise InvalidKeyFormatError("Unknown pre-key type")
        try:
            key_id = int(data["id"])
            pub = b64u_decode(data["pub"])
        except (KeyError, ValueError) as exc:
            raise InvalidKeyFormatError("Invalid pre-key id or pub") from exc

        priv_raw = data.get("priv")
        sig_raw = data.get("sig")
        priv = b64u_decode(priv_raw) if isinstance(priv_raw, str) else None
        sig = b64u_decode(sig_raw) if isinstance(sig_raw, str) else None

        return cls(
            key_id=key_id,
            public_key=pub,
            private_key=priv,
            signature=sig,
            kind=str(data["type"]),
        )

