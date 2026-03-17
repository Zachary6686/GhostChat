"""
Ed25519 identity for GhostChat client.

Public key = user ID. Private key stored locally (file-based).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from crypto.identity import IdentityKeyPair
from crypto.serialization import SerializedIdentity, b64u_decode, b64u_encode

logger = logging.getLogger(__name__)

IDENTITY_VERSION = 1


def generate_identity() -> IdentityKeyPair:
    """Create a new Ed25519 identity key pair."""
    return IdentityKeyPair.generate()


def _identity_path(path: Optional[Path] = None) -> Path:
    if path is not None:
        return Path(path)
    return Path.cwd() / "identity.json"


def save_identity(
    keypair: IdentityKeyPair,
    path: Optional[Path] = None,
) -> Path:
    """
    Persist identity to a JSON file. No plaintext private key in logs.
    """
    out = _identity_path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "v": IDENTITY_VERSION,
        "pub": b64u_encode(keypair.public_key),
        "priv": b64u_encode(keypair.private_key),
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=0)
    logger.info("Identity saved to %s", out)
    return out


def load_identity(path: Optional[Path] = None) -> IdentityKeyPair:
    """
    Load identity from file. Raises FileNotFoundError or crypto.serialization errors.
    """
    p = _identity_path(path)
    with open(p, "r", encoding="utf-8") as f:
        data = json.load(f)
    if data.get("v") != IDENTITY_VERSION:
        raise ValueError("Unsupported identity file version")
    pub = b64u_decode(data["pub"])
    priv = b64u_decode(data["priv"])
    return IdentityKeyPair(public_key=pub, private_key=priv)


def public_key_base64(keypair: IdentityKeyPair) -> str:
    """Pretty-print public key as base64 (URL-safe, no padding)."""
    return b64u_encode(keypair.public_key)
