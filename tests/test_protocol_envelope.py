from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from protocol.envelope import ProtocolEnvelope, CURRENT_VERSION


def test_envelope_serialization_roundtrip() -> None:
    env = ProtocolEnvelope(
        version=CURRENT_VERSION,
        session_id=b"session1",
        sender_ratchet_key=b"rk",
        message_number=5,
        previous_chain_length=3,
        ciphertext=b"cipher",
        nonce=b"",
        meta={"foo": "bar"},
    )
    data = env.to_dict()
    env2 = ProtocolEnvelope.from_dict(data)

    assert env2.version == env.version
    assert env2.session_id == env.session_id
    assert env2.sender_ratchet_key == env.sender_ratchet_key
    assert env2.message_number == env.message_number
    assert env2.previous_chain_length == env.previous_chain_length
    assert env2.ciphertext == env.ciphertext
    assert env2.nonce == env.nonce
    assert env2.meta == env.meta


def test_envelope_malformed_rejected() -> None:
    # Missing required field
    bad = {
        "v": CURRENT_VERSION,
        "sid": "AA",
        # "rk" missing
        "n": 0,
        "pn": 0,
        "ct": "AA",
        "nonce": "",
        "meta": {},
    }
    try:
        ProtocolEnvelope.from_dict(bad)
    except ValueError:
        pass
    else:  # pragma: no cover - defensive
        raise AssertionError("Expected ValueError for malformed envelope")

