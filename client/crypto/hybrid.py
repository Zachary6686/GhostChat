"""
Hybrid key agreement abstraction for GhostChat client.

- Domain-separated combination of classical (X25519) and optional PQC (ML-KEM/Kyber) shared secrets.
- Algorithm-suite transcript binding so downgrade and suite mismatch are detectable.
"""

from __future__ import annotations

from typing import Optional

from crypto.hkdf import hkdf_derive

# Re-export suite constants for use in X3DH and bundles.
from crypto.pqc import (
    ALGORITHM_SUITE_CLASSICAL,
    ALGORITHM_SUITE_HYBRID_KYBER,
)

# HKDF domain separation: different info strings for classical-only vs hybrid.
# Ensures combined secret is bound to the algorithm choice.
HYBRID_COMBINE_SALT = b"ghostchat-hybrid-combine-v1"
HYBRID_COMBINE_INFO = b"ghostchat-x3dh-hybrid-combine-v1"
CLASSICAL_ONLY_INFO = b"ghostchat-x3dh-classical-only-v1"


def combine_shared_secrets(
    classical_shared: bytes,
    pq_shared: Optional[bytes],
    algorithm_suite: bytes,
) -> bytes:
    """
    Combine classical (X25519) and optional PQC shared secrets with domain separation.

    - Classical-only: single HKDF step with CLASSICAL_ONLY_INFO.
    - Hybrid: first combine classical || pq with HYBRID_COMBINE_INFO, then derive 32 bytes.
    Algorithm_suite is not used as HKDF info here but must match the handshake transcript.
    """
    if pq_shared is None or len(pq_shared) == 0:
        if algorithm_suite != ALGORITHM_SUITE_CLASSICAL:
            raise ValueError("Algorithm suite must be classical when pq_shared is None")
        return hkdf_derive(
            ikm=classical_shared,
            salt=HYBRID_COMBINE_SALT,
            info=CLASSICAL_ONLY_INFO,
            length=32,
        )
    # Hybrid: domain-separated combination so classical and PQ are not interchangeable.
    combined_ikm = classical_shared + pq_shared
    return hkdf_derive(
        ikm=combined_ikm,
        salt=HYBRID_COMBINE_SALT,
        info=HYBRID_COMBINE_INFO,
        length=32,
    )


def is_hybrid_suite(algorithm_suite: bytes) -> bool:
    """Return True if the suite is a hybrid (X25519 + PQC) suite."""
    return algorithm_suite == ALGORITHM_SUITE_HYBRID_KYBER
