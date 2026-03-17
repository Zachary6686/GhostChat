from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from crypto.identity import IdentityKeyPair
from crypto.serialization import SerializedIdentity


def test_ed25519_identity_generation_and_roundtrip() -> None:
    identity = IdentityKeyPair.generate()
    assert len(identity.public_key) == 32
    assert len(identity.private_key) == 32

    message = b"ghostchat-identity-test"
    sig = identity.sign(message)
    identity.verify(message, sig)  # should not raise

    serialized = identity.serialize().to_dict()
    deserialized = SerializedIdentity.from_dict(serialized)
    identity2 = IdentityKeyPair.deserialize(deserialized)
    assert identity2.public_key == identity.public_key
    assert identity2.private_key == identity.private_key

