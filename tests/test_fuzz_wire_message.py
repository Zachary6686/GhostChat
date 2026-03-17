from __future__ import annotations

"""
Property tests for wire-level and bundle parsers.

Goals:
- Exercise wire_message_from_dict, ProtocolEnvelope.from_dict,
  SealedOuterEnvelope.from_dict, and PeerBundle.from_dict with a wide
  variety of malformed and semi-valid inputs.
- Ensure malformed inputs fail closed (explicit project errors or ValueError),
  never hang, and never accept clearly invalid structure.
- Check that legitimately produced messages/bundles round-trip under parsing.

Out of scope:
- Cryptographic strength or key distribution; these tests focus purely on
  parsing, types, ranges, and fail-closed behavior.
"""

import pathlib
import sys

import pytest

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
except ModuleNotFoundError:  # pragma: no cover - hypothesis is an optional dev dependency
    pytest.skip("hypothesis not installed; skipping fuzz/property tests", allow_module_level=True)

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client.crypto.double_ratchet import DoubleRatchetEngine, create_initial_state
from client.crypto.message import (
    RatchetWireMessage,
    wire_message_from_dict,
    wire_message_to_dict,
)
from client.crypto.prekey import PeerBundle, generate_prekey_bundle, serialize_bundle
from client.crypto.ratchet_errors import InvalidHeaderError
from client.crypto.ratchet_errors import SignedPreKeyVerificationError, X3DHInitializationError
from client.crypto.x3dh import x3dh_initiator
from crypto.identity import IdentityKeyPair
from protocol.envelope import ProtocolEnvelope
from protocol.sealed_sender import SealedOuterEnvelope
from tests.strategies import (
    base64ish_strings,
    invalid_counter,
    small_bytes,
    small_json_like_dicts,
    valid_counter,
)


def _make_pair() -> tuple[DoubleRatchetEngine, DoubleRatchetEngine]:
    root_key = b"0" * 32
    alice_state = create_initial_state(root_key, is_initiator=True)
    bob_state = create_initial_state(root_key, is_initiator=False)
    return DoubleRatchetEngine(alice_state), DoubleRatchetEngine(bob_state)


@settings(max_examples=50)
@given(payload=small_bytes(min_size=0, max_size=32))
def test_wire_message_roundtrip_property(payload: bytes) -> None:
    """For valid wires from the engine, wire_message_to_dict / from_dict round-trip and still decrypt."""
    alice, bob = _make_pair()
    wire = alice.ratchet_encrypt(payload)
    d = wire_message_to_dict(wire)
    parsed = wire_message_from_dict(d)
    assert isinstance(parsed, RatchetWireMessage)
    got = bob.ratchet_decrypt(parsed)
    assert got == payload


@settings(max_examples=80)
@given(data=small_json_like_dicts())
def test_wire_message_from_dict_never_silently_accepts_obviously_invalid(data: dict) -> None:
    """
    Fuzz wire_message_from_dict with small JSON-like dicts.

    If the dict is missing core fields (header / ciphertext / nonce) or has clearly
    invalid types for them, we expect InvalidHeaderError or ValueError.
    """
    # Force some invalid shapes: drop header or use wrong types with some probability.
    mutated = dict(data)
    if "header" not in mutated or not isinstance(mutated.get("header"), dict):
        mutated["header"] = mutated.get("header", {})
    if not isinstance(mutated["header"], dict):
        mutated["header"] = {}

    # Randomly assign potentially-invalid values.
    mutated["header"].setdefault("dh", base64ish_strings().example())
    mutated["header"].setdefault("n", invalid_counter().example())
    mutated["header"].setdefault("pn", invalid_counter().example())
    mutated.setdefault("ciphertext", base64ish_strings().example())
    mutated.setdefault("nonce", base64ish_strings().example())

    with pytest.raises((InvalidHeaderError, ValueError, TypeError)):
        wire_message_from_dict(mutated)


@settings(max_examples=60)
@given(env_dict=small_json_like_dicts())
def test_protocol_envelope_from_dict_fuzz(env_dict: dict) -> None:
    """
    Fuzz ProtocolEnvelope.from_dict with small JSON-like dicts.

    Either:
    - it raises ValueError on invalid/malformed envelopes, or
    - it returns an object with minimally sane fields (non-empty sid/rk/ct).
    """
    try:
        env = ProtocolEnvelope.from_dict(env_dict)
    except ValueError:
        return

    assert isinstance(env, ProtocolEnvelope)
    assert env.version == 1
    assert env.session_id
    assert env.sender_ratchet_key
    assert env.ciphertext


@settings(max_examples=60)
@given(env_dict=small_json_like_dicts())
def test_sealed_outer_envelope_from_dict_fuzz(env_dict: dict) -> None:
    """
    Fuzz SealedOuterEnvelope.from_dict with small JSON-like dicts.

    Invalid data must raise ValueError; valid objects must have non-empty
    sealed_payload and sane ttl.
    """
    try:
        env = SealedOuterEnvelope.from_dict(env_dict)
    except ValueError:
        return

    assert isinstance(env, SealedOuterEnvelope)
    assert env.version == 1
    assert isinstance(env.recipient_locator, str) and env.recipient_locator
    assert env.ttl >= 0
    assert isinstance(env.sealed_payload, bytes) and len(env.sealed_payload) >= 12 + 16


@settings(max_examples=40)
@given(include_pq=st.booleans())
def test_peer_bundle_roundtrip_and_fuzz_mutations(include_pq: bool) -> None:
    """
    Round-trip serialize/parse of PeerBundle must succeed and produce consistent fields.
    Simple fuzz mutations must be rejected with ValueError or X3DHInitializationError.
    """
    identity = IdentityKeyPair.generate()
    if include_pq:
        from crypto.pqc import get_testing_pq_backend

        bundle = generate_prekey_bundle(identity, opk_count=2, pq_backend=get_testing_pq_backend())
    else:
        bundle = generate_prekey_bundle(identity, opk_count=2)

    d = serialize_bundle(bundle, for_upload=True)
    pb = PeerBundle.from_dict(d)
    assert len(pb.identity_pub) == 32
    assert len(pb.identity_dh_pub) == 32
    assert len(pb.spk_pub) == 32

    # Fuzz: remove or corrupt some fields and ensure parsing fails.
    mutations = []
    # Drop identity_pub
    bad1 = dict(d)
    bad1.pop("identity_pub", None)
    mutations.append(bad1)
    # Bad SPK signature
    bad2 = dict(d)
    spk2 = dict(bad2["spk"])
    spk2["sig"] = base64ish_strings().example()
    bad2["spk"] = spk2
    mutations.append(bad2)
    # Missing algorithm_suite when pq_pub present
    if "pq_pub" in d:
        bad3 = dict(d)
        bad3.pop("algorithm_suite", None)
        mutations.append(bad3)

    for m in mutations:
        with pytest.raises((ValueError, SignedPreKeyVerificationError, X3DHInitializationError)):
            # Some malformed bundles may fail during PeerBundle.from_dict,
            # others when passed into x3dh_initiator.
            try:
                bad_pb = PeerBundle.from_dict(m)
            except ValueError:
                continue
            eph = IdentityKeyPair.generate()
            from nacl.public import PrivateKey as X25519PrivateKey

            eph_dh = X25519PrivateKey.generate()
            x3dh_initiator(eph_dh.encode(), eph_dh, bad_pb, None)

