#!/bin/sh

# Group messaging demo for GhostChat.
# This runs pytest scenarios that demonstrate:
# - Group creation and basic messaging.
# - Epoch rotation when adding Dave (cannot decrypt prior epochs).
# - Epoch rotation when removing Charlie (cannot decrypt future epochs).

set -e

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "Running group messaging demo (create + send)..."
python -m pytest tests/test_group_message_flow.py::test_send_valid_group_message_decrypt_at_recipients -v

echo "Running group epoch rotation demo (add Dave, cannot decrypt prior)..."
python -m pytest tests/test_group_message_flow.py::test_add_dave_epoch_rotates_dave_cannot_decrypt_prior -v

echo "Running group epoch rotation demo (remove Charlie, cannot decrypt future)..."
python -m pytest tests/test_group_message_flow.py::test_remove_charlie_epoch_rotates_charlie_cannot_decrypt_future -v

