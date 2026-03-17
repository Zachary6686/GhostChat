#!/usr/bin/env sh
# GhostChat full validation: Python check, deps hint, then run test stages with PASS/FAIL summary.
# Run from repository root (ghostchat/): ./scripts/validate_all.sh

set -e

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

echo "=== GhostChat validation (root: $ROOT) ==="

# 1. Python available
if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
  echo "FAIL: Python not found. Install Python and ensure it is on PATH."
  exit 1
fi
PYTHON=""
if command -v python3 >/dev/null 2>&1; then PYTHON=python3; else PYTHON=python; fi
echo "Using: $PYTHON ($($PYTHON --version 2>&1))"

# 2. Dependencies hint only (do not auto-install)
if ! $PYTHON -c "import pytest" 2>/dev/null; then
  echo "Dependencies missing. Install with: pip install -r requirements.txt"
  echo "Then activate your venv if you use one (e.g. source .venv/bin/activate) and re-run."
  exit 1
fi

FAILED=""
PASSED=""

run_stage() {
  name="$1"
  shift
  echo ""
  echo "--- $name ---"
  if $PYTHON -m pytest "$@" -v --tb=short 2>&1; then
    PASSED="$PASSED\n  $name"
    return 0
  else
    FAILED="$FAILED\n  $name"
    return 1
  fi
}

# 3. Core pytest suite (identity, prekeys, x3dh, ratchet, envelope, replay, fork, sealed_sender)
run_stage "Core (identity, prekeys, x3dh, ratchet, envelope, replay, fork, sealed_sender)" \
  tests/test_identity.py tests/test_prekeys.py tests/test_x3dh.py \
  tests/test_ratchet_basic.py tests/test_ratchet_out_of_order.py \
  tests/test_protocol_envelope.py tests/test_replay_protection.py tests/test_fork_detection.py \
  tests/test_sealed_sender.py || true

# 4. Protocol integration tests
run_stage "Protocol integration" tests/test_protocol_integration.py || true

# 5. End-to-end session tests (subset of protocol integration)
run_stage "E2E session" \
  tests/test_protocol_integration.py::test_protocol_integration_end_to_end \
  tests/test_protocol_integration.py::test_end_to_end_via_relay_router || true

# 6. Group messaging tests
run_stage "Group messaging" \
  tests/test_group_state.py tests/test_group_membership.py tests/test_group_message_flow.py \
  tests/test_group_mls.py tests/test_group_epoch.py || true

# 7. Network hardening tests
run_stage "Network hardening" \
  tests/test_mix_delay.py tests/test_cover_traffic.py tests/test_dummy_packets.py \
  tests/test_network_cover_and_dummy.py tests/test_network_mix_and_timing.py tests/test_timing_defense.py || true

# Summary
echo ""
echo "========== SUMMARY =========="
if [ -n "$FAILED" ]; then
  echo "FAILED:$FAILED"
  echo "PASSED:$PASSED"
  echo "OVERALL: FAIL"
  exit 1
fi
echo "PASSED:$PASSED"
echo "OVERALL: PASS"
exit 0
