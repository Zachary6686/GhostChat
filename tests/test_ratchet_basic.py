from __future__ import annotations

import os
import pathlib
import sys

import pytest
from cryptography.exceptions import InvalidTag

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nacl.public import PrivateKey as X25519PrivateKey

from ratchet.double_ratchet import DoubleRatchet, EncryptedMessage


def _linked_sessions() -> tuple[DoubleRatchet, DoubleRatchet]:
    root_key = os.urandom(32)
    alice_dh = X25519PrivateKey.generate()
    bob_dh = X25519PrivateKey.generate()

    alice = DoubleRatchet(
        root_key=root_key,
        dhs=alice_dh,
        dhr=bytes(bob_dh.public_key),
        is_initiator=True,
    )
    bob = DoubleRatchet(
        root_key=root_key,
        dhs=bob_dh,
        dhr=bytes(alice_dh.public_key),
        is_initiator=False,
    )
    return alice, bob


def test_basic_send_receive() -> None:
    alice, bob = _linked_sessions()

    plaintext = b"hello from alice"
    msg = alice.encrypt(plaintext)

    received = bob.decrypt(msg)
    assert received == plaintext

    reply = b"hi alice, this is bob"
    msg2 = bob.encrypt(reply)
    received2 = alice.decrypt(msg2)
    assert received2 == reply


def test_failed_decrypt_does_not_advance_receiving_chain() -> None:
    alice, bob = _linked_sessions()

    msg = alice.encrypt(b"authentic")
    forged = EncryptedMessage(header=msg.header, ciphertext=bytes(32))

    with pytest.raises(InvalidTag):
        bob.decrypt(forged)

    assert bob.state.Nr == 0
    assert bob.decrypt(msg) == b"authentic"


def test_failed_new_dh_decrypt_does_not_commit_ratchet_step() -> None:
    alice, bob = _linked_sessions()

    first = alice.encrypt(b"first")
    assert bob.decrypt(first) == b"first"
    next_msg = alice.encrypt(b"next")
    attacker_dh = bytes(X25519PrivateKey.generate().public_key)
    forged = EncryptedMessage(
        header=type(next_msg.header)(dh_pub=attacker_dh, pn=next_msg.header.pn, n=0),
        ciphertext=bytes(32),
    )

    previous_dhr = bob.state.dhr
    previous_nr = bob.state.Nr
    with pytest.raises(InvalidTag):
        bob.decrypt(forged)

    assert bob.state.dhr == previous_dhr
    assert bob.state.Nr == previous_nr
    assert bob.decrypt(next_msg) == b"next"

