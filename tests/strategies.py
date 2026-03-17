from __future__ import annotations

"""
Shared Hypothesis strategies for GhostChat tests.

These strategies focus on:
- base64-like strings (valid and invalid),
- bounded integers for protocol counters,
- small byte strings used in envelopes and ciphertexts.

They are intentionally conservative in size for CI friendliness.
"""

from typing import Any, Dict

from hypothesis import strategies as st


UINT32_MAX = 0xFFFF_FFFF


def valid_counter() -> st.SearchStrategy[int]:
    """Valid message/counter values: [0, 2^32-1]."""
    return st.integers(min_value=0, max_value=UINT32_MAX)


def invalid_counter() -> st.SearchStrategy[int]:
    """Invalid message/counter values: negatives or > 2^32-1."""
    below = st.integers(min_value=-2**31, max_value=-1)
    above = st.integers(min_value=UINT32_MAX + 1, max_value=UINT32_MAX * 4)
    return below | above


def small_bytes(min_size: int = 0, max_size: int = 64) -> st.SearchStrategy[bytes]:
    """Small byte strings, used for keys, nonces, and payloads."""
    return st.binary(min_size=min_size, max_size=max_size)


def base64ish_strings() -> st.SearchStrategy[str]:
    """
    Strings that look somewhat like base64-url data, plus obviously invalid ones.

    This is used to exercise base64 decoders in a controlled way without
    generating megabyte-scale inputs.
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    valid = st.text(alphabet=alphabet, min_size=0, max_size=64)
    invalid = st.text(
        alphabet=st.characters(blacklist_characters="\n\r"),
        min_size=1,
        max_size=32,
    ).filter(lambda s: any(c not in alphabet for c in s))
    return st.one_of(valid, invalid)


def small_json_like_dicts() -> st.SearchStrategy[Dict[str, Any]]:
    """Small JSON-like dicts with string keys and mixed simple values."""
    simple_values = st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-2**31, max_value=2**31 - 1),
        st.floats(allow_nan=False, allow_infinity=False),
        st.text(min_size=0, max_size=32),
    )
    return st.dictionaries(
        keys=st.text(min_size=1, max_size=16),
        values=simple_values,
        min_size=0,
        max_size=10,
    )

