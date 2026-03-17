from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

"""
Deprecated: kept for backward compatibility during test migration.
New tests live in `test_cover_traffic.py`.
"""


