APP_PYTHONPATH=src
PYTHON=python3

.PHONY: lint test verify demo scan-unsafe scan-safe calibrate

lint:
	PYTHONPATH=$(APP_PYTHONPATH) $(PYTHON) -m ruff check .

test:
	PYTHONPATH=$(APP_PYTHONPATH) $(PYTHON) -m pytest -q

verify: lint test

scan-unsafe:
	PYTHONPATH=$(APP_PYTHONPATH) $(PYTHON) -m privacy_review_agent.cli scan --path tests/fixtures/unsafe --format md

scan-safe:
	PYTHONPATH=$(APP_PYTHONPATH) $(PYTHON) -m privacy_review_agent.cli scan --path tests/fixtures/safe --format md

calibrate:
	PYTHONPATH=$(APP_PYTHONPATH) $(PYTHON) -m privacy_review_agent.cli calibrate --fixture-set tests/fixtures

demo:
	@echo "1) Unsafe fixture should block (exit 2)"
	-@PYTHONPATH=$(APP_PYTHONPATH) $(PYTHON) -m privacy_review_agent.cli scan --path tests/fixtures/unsafe --format md >/tmp/privacy-unsafe.md ; \
	code=$$?; echo "unsafe_exit=$$code"; head -n 14 /tmp/privacy-unsafe.md
	@echo ""
	@echo "2) Safe fixture should pass (exit 0)"
	@PYTHONPATH=$(APP_PYTHONPATH) $(PYTHON) -m privacy_review_agent.cli scan --path tests/fixtures/safe --format md >/tmp/privacy-safe.md ; \
	code=$$?; echo "safe_exit=$$code"; cat /tmp/privacy-safe.md
