#!/bin/sh

# Minimal relay demo for GhostChat.
# This prototype uses an in-process relay in tests rather than a
# standalone production server. This script runs a relay integration
# test to demonstrate routing and sealed sender behavior.

set -e

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "Running minimal relay integration test (in-process)..."
python -m pytest tests/test_protocol_integration.py::test_end_to_end_via_relay_router -v

