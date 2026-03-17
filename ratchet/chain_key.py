from __future__ import annotations

"""
Chain key derivation wrappers.

This module provides a clearer name for the chain-key KDF used in the
double ratchet. It delegates to the existing `kdf` implementation to
avoid changing any logic.
"""

from .kdf import RatchetKDFParameters, kdf_chain

__all__ = ["RatchetKDFParameters", "kdf_chain"]

