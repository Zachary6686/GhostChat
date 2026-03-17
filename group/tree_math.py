from __future__ import annotations

"""
Tree math helpers for the MLS-inspired group key schedule.

The current implementation uses a fixed-capacity full binary tree for a
small number of members. This module centralizes index calculations and
provides a convenient place for future extensions.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class TreeShape:
    leaves: int

    @property
    def leaf_offset(self) -> int:
        return self.leaves - 1

    @property
    def total_nodes(self) -> int:
        return 2 * self.leaves - 1


def parent(index: int) -> int | None:
    if index == 0:
        return None
    return (index - 1) // 2


def left_child(index: int) -> int:
    return 2 * index + 1


def right_child(index: int) -> int:
    return 2 * index + 2

