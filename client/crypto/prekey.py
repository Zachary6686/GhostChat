"""
PreKey bundle system for GhostChat client.

Identity (Ed25519), Signed PreKey (X25519 + signature), One-Time PreKeys (X25519).
Supports bundle generation, SPK signing, and serialization for server upload / fetch.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from nacl.public import PrivateKey as X25519PrivateKey
from nacl.public import PublicKey as X25519PublicKey

from crypto.identity import IdentityKeyPair
from crypto.prekeys import OneTimePreKey, PreKeyBundle, SignedPreKey
from crypto.serialization import b64u_decode, b64u_encode

from client.crypto.ratchet_errors import OneTimePreKeyReuseError, SignedPreKeyVerificationError

logger = logging.getLogger(__name__)

BUNDLE_VERSION = 1

# Algorithm suite for classical-only bundles (no PQC).
from client.crypto.hybrid import ALGORITHM_SUITE_CLASSICAL  # noqa: E402
from crypto.pqc import ALGORITHM_SUITE_HYBRID_KYBER  # noqa: E402


@dataclass
class ClientPreKeyBundle:
    """
    Client-side PreKey bundle: identity (Ed25519), identity_dh (X25519 for X3DH),
    signed prekey, one-time prekeys. Optional PQC (ML-KEM/Kyber) for hybrid mode.
    """

    identity: IdentityKeyPair
    identity_dh_private: bytes  # X25519 for DH1/DH2 in X3DH
    signed_prekey: SignedPreKey
    one_time_prekeys: Dict[int, OneTimePreKey] = field(default_factory=dict)
    used_opk_ids: List[int] = field(default_factory=list)
    pq_public_key: Optional[bytes] = None
    pq_secret_key: Optional[bytes] = None
    algorithm_suite: bytes = ALGORITHM_SUITE_CLASSICAL

    @property
    def identity_dh_public(self) -> bytes:
        return bytes(X25519PrivateKey(self.identity_dh_private).public_key)

    def verify_spk(self) -> None:
        """Verify signed prekey signature under identity key. Raises SignedPreKeyVerificationError on failure."""
        try:
            self.signed_prekey.verify(self.identity)
        except Exception as e:
            raise SignedPreKeyVerificationError("Signed prekey signature invalid") from e

    def consume_one_time_prekey(self, key_id: int) -> OneTimePreKey:
        """
        Atomically remove and return OPK by id. Raises OneTimePreKeyReuseError if already used or not found.
        """
        if key_id in self.used_opk_ids:
            raise OneTimePreKeyReuseError("One-time prekey already used")
        opk = self.one_time_prekeys.pop(key_id, None)
        if opk is None:
            raise OneTimePreKeyReuseError("One-time prekey not found")
        self.used_opk_ids.append(key_id)
        return opk

    def get_one_time_prekey(self, key_id: int) -> Optional[OneTimePreKey]:
        return self.one_time_prekeys.get(key_id)


def sign_prekey(identity: IdentityKeyPair, spk_key_id: int = 1) -> SignedPreKey:
    """Create a signed prekey (X25519) signed with the identity key."""
    return SignedPreKey.generate(spk_key_id, identity)


def generate_prekey_bundle(
    identity: IdentityKeyPair,
    *,
    identity_dh_private: Optional[bytes] = None,
    spk_id: int = 1,
    opk_start_id: int = 1000,
    opk_count: int = 10,
    pq_backend: Optional[Any] = None,
) -> ClientPreKeyBundle:
    """
    Generate a full PreKey bundle: identity_dh (X25519), SPK (signed by identity), OPKs.
    If identity_dh_private is None, a new X25519 key pair is generated.
    If pq_backend is provided (PQKEMBackend), adds PQ keypair and sets algorithm_suite for hybrid mode.
    """
    if identity_dh_private is None:
        identity_dh_private = bytes(X25519PrivateKey.generate())
    spk = sign_prekey(identity, spk_id)
    opks: Dict[int, OneTimePreKey] = {}
    for i in range(opk_count):
        kid = opk_start_id + i
        opks[kid] = OneTimePreKey.generate(kid)
    pq_pub: Optional[bytes] = None
    pq_sk: Optional[bytes] = None
    algorithm_suite: bytes = ALGORITHM_SUITE_CLASSICAL
    if pq_backend is not None:
        pq_pub, pq_sk = pq_backend.generate_keypair()
        algorithm_suite = pq_backend.algorithm_suite()
    bundle = ClientPreKeyBundle(
        identity=identity,
        identity_dh_private=identity_dh_private,
        signed_prekey=spk,
        one_time_prekeys=opks,
        pq_public_key=pq_pub,
        pq_secret_key=pq_sk,
        algorithm_suite=algorithm_suite,
    )
    bundle.verify_spk()
    return bundle


def serialize_bundle(bundle: ClientPreKeyBundle, for_upload: bool = True) -> Dict[str, Any]:
    """
    Serialize bundle for server upload (public only) or local storage (includes private).
    for_upload=True: identity_pub, identity_dh_pub, spk, opks; optional pq_pub and algorithm_suite.
    for_upload=False: same plus identity_dh_private, spk_private, opk_privates, optional pq_secret_key.
    """
    spk_ser = bundle.signed_prekey.serialize(include_private=not for_upload)
    out: Dict[str, Any] = {
        "v": BUNDLE_VERSION,
        "identity_pub": b64u_encode(bundle.identity.public_key),
        "identity_dh_pub": b64u_encode(bundle.identity_dh_public),
        "spk": {
            "key_id": spk_ser.key_id,
            "pub": b64u_encode(spk_ser.public_key),
            "sig": b64u_encode(spk_ser.signature) if spk_ser.signature else None,
        },
        "opks": [
            {"key_id": opk.key_id, "pub": b64u_encode(opk.public_key)}
            for opk in sorted(bundle.one_time_prekeys.values(), key=lambda k: k.key_id)
        ],
    }
    if bundle.pq_public_key is not None:
        out["pq_pub"] = b64u_encode(bundle.pq_public_key)
        out["algorithm_suite"] = b64u_encode(bundle.algorithm_suite)
    if not for_upload:
        out["identity_dh_priv"] = b64u_encode(bundle.identity_dh_private)
        out["spk"]["priv"] = b64u_encode(bundle.signed_prekey.private_key)
        for i, opk in enumerate(sorted(bundle.one_time_prekeys.values(), key=lambda k: k.key_id)):
            out["opks"][i]["priv"] = b64u_encode(opk.private_key)
        out["used_opk_ids"] = bundle.used_opk_ids
        if bundle.pq_secret_key is not None:
            out["pq_priv"] = b64u_encode(bundle.pq_secret_key)
    return out


def serialize_bundle_for_upload(bundle: ClientPreKeyBundle) -> str:
    """JSON string of public bundle for server."""
    return json.dumps(serialize_bundle(bundle, for_upload=True))


@dataclass(frozen=True)
class PeerBundle:
    """Parsed public PreKey bundle from a peer (for X3DH initiator). Optional PQC for hybrid."""

    identity_pub: bytes  # Ed25519 (for SPK verification)
    identity_dh_pub: bytes  # X25519 (for DH2)
    spk_id: int
    spk_pub: bytes
    spk_sig: bytes
    opks: List[tuple[int, bytes]]  # (key_id, pub) optionally one used for DH4
    pq_pub: Optional[bytes] = None
    algorithm_suite: bytes = ALGORITHM_SUITE_CLASSICAL

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PeerBundle":
        if data.get("v") != BUNDLE_VERSION:
            raise ValueError("Unsupported bundle version")
        try:
            identity_pub_enc = data["identity_pub"]
            identity_dh_pub_enc = data["identity_dh_pub"]
            spk = data["spk"]
            opks_raw = data.get("opks", [])
        except KeyError as exc:
            raise ValueError(f"Malformed peer bundle: missing field {exc}") from exc
        identity_pub = b64u_decode(identity_pub_enc)
        identity_dh_pub = b64u_decode(identity_dh_pub_enc)
        try:
            spk_id = int(spk["key_id"])
            spk_pub = b64u_decode(spk["pub"])
            spk_sig = b64u_decode(spk["sig"]) if spk.get("sig") else b""
        except (KeyError, ValueError) as exc:
            raise ValueError("Malformed peer bundle: invalid or missing SPK fields") from exc
        opks: list[tuple[int, bytes]] = []
        for o in opks_raw:
            try:
                kid = int(o["key_id"])
                pub = b64u_decode(o["pub"])
            except (KeyError, ValueError) as exc:
                raise ValueError("Malformed peer bundle: invalid OPK entry") from exc
            opks.append((kid, pub))
        pq_pub = b64u_decode(data["pq_pub"]) if data.get("pq_pub") else None
        if pq_pub is not None and "algorithm_suite" not in data:
            raise ValueError("Peer bundle with pq_pub must include algorithm_suite")
        algorithm_suite = (
            b64u_decode(data["algorithm_suite"])
            if data.get("algorithm_suite")
            else ALGORITHM_SUITE_CLASSICAL
        )
        return cls(
            identity_pub=identity_pub,
            identity_dh_pub=identity_dh_pub,
            spk_id=spk_id,
            spk_pub=spk_pub,
            spk_sig=spk_sig,
            opks=opks,
            pq_pub=pq_pub,
            algorithm_suite=algorithm_suite,
        )


def load_bundle_from_file(path: Path) -> Dict[str, Any]:
    """Load serialized bundle (e.g. private) from JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def deserialize_bundle_private(data: Dict[str, Any], identity: IdentityKeyPair) -> ClientPreKeyBundle:
    """Reconstruct ClientPreKeyBundle from private serialized form (e.g. from file)."""
    if data.get("v") != BUNDLE_VERSION:
        raise ValueError("Unsupported bundle version")
    identity_dh_private = b64u_decode(data["identity_dh_priv"])
    spk_d = data["spk"]
    from crypto.prekeys import SignedPreKey
    from crypto.serialization import SerializedPreKey

    spk_ser = SerializedPreKey(
        key_id=int(spk_d["key_id"]),
        public_key=b64u_decode(spk_d["pub"]),
        private_key=b64u_decode(spk_d["priv"]) if spk_d.get("priv") else None,
        signature=b64u_decode(spk_d["sig"]) if spk_d.get("sig") else None,
        kind="spk",
    )
    spk = SignedPreKey.deserialize(spk_ser)
    opks = {}
    used = data.get("used_opk_ids", [])
    for o in data.get("opks", []):
        kid = int(o["key_id"])
        if kid in used:
            continue
        opk_ser = SerializedPreKey(
            key_id=kid,
            public_key=b64u_decode(o["pub"]),
            private_key=b64u_decode(o["priv"]) if o.get("priv") else None,
            signature=None,
            kind="opk",
        )
        opks[kid] = OneTimePreKey.deserialize(opk_ser)
    pq_pub = b64u_decode(data["pq_pub"]) if data.get("pq_pub") else None
    pq_priv = b64u_decode(data["pq_priv"]) if data.get("pq_priv") else None
    algo_suite = b64u_decode(data["algorithm_suite"]) if data.get("algorithm_suite") else ALGORITHM_SUITE_CLASSICAL
    return ClientPreKeyBundle(
        identity=identity,
        identity_dh_private=identity_dh_private,
        signed_prekey=spk,
        one_time_prekeys=opks,
        used_opk_ids=used,
        pq_public_key=pq_pub,
        pq_secret_key=pq_priv,
        algorithm_suite=algo_suite,
    )


def save_bundle_to_file(bundle: ClientPreKeyBundle, path: Path, for_upload: bool = False) -> None:
    """Write bundle JSON to file (private by default for local storage)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(serialize_bundle(bundle, for_upload=for_upload), f, indent=0)
    logger.info("Bundle saved to %s", path)
