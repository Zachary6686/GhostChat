# GhostChat developer convenience targets.
# Run from project root (ghostchat/): make test, make server, make client, make validate

PYTHON ?= python
PYTEST = $(PYTHON) -m pytest

.PHONY: test server client validate

# Run full test suite
test:
	$(PYTEST) tests/ -v

# Start relay demo (runs in-process relay integration test)
server:
	$(PYTEST) tests/test_protocol_integration.py::test_end_to_end_via_relay_router -v

# Run client demo (two SessionManagers, one-to-one message)
client:
	$(PYTEST) tests/test_protocol_integration.py::test_protocol_integration_end_to_end -v

# Run full validation (all test stages + PASS/FAIL summary)
validate:
	@./scripts/validate_all.sh
