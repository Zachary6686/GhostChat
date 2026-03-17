from __future__ import annotations

"""
Obfuscation helpers (skeleton).

Provides hooks for frame padding, record size randomization, or other
simple obfuscation strategies.
"""

import os


def pad_frame(data: bytes, min_size: int = 64) -> bytes:
    if len(data) >= min_size:
        return data
    padding = os.urandom(min_size - len(data))
    return data + padding

