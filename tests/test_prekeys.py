from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from crypto.errors import OneTimePreKeyExhaustedError, InvalidSignatureError
from crypto.identity import IdentityKeyPair
from crypto.prekeys import OneTimePreKey, PreKeyBundle, SignedPreKey
from crypto.serialization import SerializedPreKey


def test_signed_prekey_signature_verification() -> None:
    identity = IdentityKeyPair.generate()
    spk = SignedPreKey.generate(key_id=1, identity=identity)

    # Should verify with correct identity
    spk.verify(identity)

    # Tampering with public key should fail verification
    tampered = SignedPreKey(
        key_id=spk.key_id,
        public_key=bytes([b ^ 0x01 for b in spk.public_key]),
        private_key=spk.private_key,
        signature=spk.signature,
    )
    try:
        tampered.verify(identity)
    except InvalidSignatureError:
        pass
    else:  # pragma: no cover - defensive
        raise AssertionError("Expected InvalidSignatureError for tampered SPK")


def test_one_time_prekey_one_time_consumption() -> None:
    identity = IdentityKeyPair.generate()
    bundle = PreKeyBundle.generate(identity=identity, opk_count=2)

    ids_before = bundle.peek_one_time_prekey_ids()
    assert len(ids_before) == 2

    first = bundle.consume_one_time_prekey()
    assert first.key_id in ids_before
    assert first.key_id not in bundle.peek_one_time_prekey_ids()

    second = bundle.consume_one_time_prekey()
    assert second.key_id in ids_before
    assert second.key_id not in bundle.peek_one_time_prekey_ids()

    assert set(bundle.peek_one_time_prekey_ids()) == set()

    # Now the pool is empty; further consumption should raise.
    try:
        bundle.consume_one_time_prekey()
    except OneTimePreKeyExhaustedError:
        pass
    else:  # pragma: no cover - defensive
        raise AssertionError("Expected OneTimePreKeyExhaustedError when OPKs exhausted")


def test_prekey_serialization_roundtrip() -> None:
    identity = IdentityKeyPair.generate()
    spk = SignedPreKey.generate(key_id=7, identity=identity)
    opk = OneTimePreKey.generate(key_id=42)

    spk_ser = spk.serialize(include_private=True).to_dict()
    opk_ser = opk.serialize(include_private=True).to_dict()

    spk_back = SignedPreKey.deserialize(SerializedPreKey.from_dict(spk_ser))
    opk_back = OneTimePreKey.deserialize(SerializedPreKey.from_dict(opk_ser))

    assert spk_back.key_id == spk.key_id
    assert spk_back.public_key == spk.public_key
    assert spk_back.private_key == spk.private_key
    assert spk_back.signature == spk.signature

    assert opk_back.key_id == opk.key_id
    assert opk_back.public_key == opk.public_key
    assert opk_back.private_key == opk.private_key


def test_public_bundle_serialization_contains_only_public_material() -> None:
    identity = IdentityKeyPair.generate()
    bundle = PreKeyBundle.generate(identity=identity, opk_count=3)
    bundle_dict = bundle.serialize_public_bundle()

    assert "identity_pub" in bundle_dict
    assert "spk" in bundle_dict
    assert "opks" in bundle_dict

    spk_dict = bundle_dict["spk"]
    assert spk_dict["priv"] is None
    assert isinstance(spk_dict["pub"], str)
    assert isinstance(spk_dict["sig"], str)

    for opk_dict in bundle_dict["opks"]:
        assert opk_dict["priv"] is None
        assert isinstance(opk_dict["pub"], str)

