#!/bin/sh

# One-to-one client demo for GhostChat.
# This runs a pytest scenario where two SessionManager instances
# ("alice" and "bob") exchange an encrypted message end-to-end.

set -e

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "Running end-to-end one-to-one session demo..."
python -m pytest tests/test_protocol_integration.py::test_protocol_integration_end_to_end -v

