from __future__ import annotations

"""
Message key helpers for the double ratchet.

In this prototype, message keys are derived alongside chain keys in
`kdf_chain`. This module exists to align the repository structure with
the intended architecture and to provide a clear place for any future
message-key specific utilities.
"""

from .kdf import kdf_chain, RatchetKDFParameters

__all__ = ["kdf_chain", "RatchetKDFParameters"]

