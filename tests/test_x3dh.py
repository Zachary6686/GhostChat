from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from crypto.hkdf import hkdf_derive
from crypto.identity import IdentityKeyPair
from crypto.pqc import get_testing_pq_backend
from crypto.prekeys import OneTimePreKey, PreKeyBundle
from crypto.x3dh import (
    X3DHParameters,
    X3DHSessionSecrets,
    perform_classical_x3dh_handshake,
    perform_hybrid_x3dh_handshake,
)


def test_hkdf_derivation_determinism() -> None:
    params = X3DHParameters()
    ikm = b"input-keying-material"
    salt = params.salt
    info = params.info

    k1 = hkdf_derive(ikm=ikm, salt=salt, info=info, length=params.key_length)
    k2 = hkdf_derive(ikm=ikm, salt=salt, info=info, length=params.key_length)
    assert k1 == k2

    # Changing any input should change the derived key with overwhelming
    # probability; we simply assert inequality here.
    k3 = hkdf_derive(ikm=ikm + b"x", salt=salt, info=info, length=params.key_length)
    assert k1 != k3


def test_x3dh_classical_shared_secret_agreement() -> None:
    identity = IdentityKeyPair.generate()
    bundle = PreKeyBundle.generate(identity=identity, opk_count=1)
    bundle.verify_spk()

    opk_id = bundle.peek_one_time_prekey_ids()[0]
    opk = bundle.one_time_prekeys[opk_id]

    secrets_init, secrets_resp, eph_pub = perform_classical_x3dh_handshake(
        responder_spk=bundle.signed_prekey,
        responder_opk=opk,
    )

    assert isinstance(eph_pub, bytes)
    assert len(secrets_init.root_key) == len(secrets_resp.root_key)
    assert secrets_init.root_key == secrets_resp.root_key
    assert secrets_init.classical_secret == secrets_resp.classical_secret
    assert secrets_init.pq_secret is None
    assert secrets_resp.pq_secret is None


def test_x3dh_hybrid_includes_pq_component() -> None:
    identity = IdentityKeyPair.generate()
    bundle = PreKeyBundle.generate(identity=identity, opk_count=1)
    bundle.verify_spk()

    opk_id = bundle.peek_one_time_prekey_ids()[0]
    opk = bundle.one_time_prekeys[opk_id]

    pq_backend = get_testing_pq_backend()

    hybrid_init, hybrid_resp, eph_pub, pq_ct = perform_hybrid_x3dh_handshake(
        responder_spk=bundle.signed_prekey,
        responder_opk=opk,
        pq_backend=pq_backend,
    )

    assert isinstance(eph_pub, bytes)
    assert isinstance(pq_ct, bytes)
    assert isinstance(hybrid_init, X3DHSessionSecrets)
    assert isinstance(hybrid_resp, X3DHSessionSecrets)

    # Root keys must agree.
    assert hybrid_init.root_key == hybrid_resp.root_key

    # PQ secrets must be present and equal.
    assert hybrid_init.pq_secret is not None
    assert hybrid_resp.pq_secret is not None
    assert hybrid_init.pq_secret == hybrid_resp.pq_secret

    # Classical+PQ hybrid must differ from a classical-only root key (with
    # overwhelming probability) when run over the same classical inputs.
    classical_init, classical_resp, _ = perform_classical_x3dh_handshake(
        responder_spk=bundle.signed_prekey,
        responder_opk=opk,
    )
    assert hybrid_init.root_key != classical_init.root_key
    assert hybrid_resp.root_key != classical_resp.root_key

