.PHONY: install test lint format-check audit security-check run package

install:
	python -m pip install -r requirements-dev.txt

test:
	python -m pytest -q

lint:
	python -m ruff check .

format-check:
	python -m ruff format --check .

audit:
	python -m pip_audit -r requirements.txt
	python -m bandit -q -r url_guard_bot scripts

security-check:
	python scripts/security_check.py

run:
	python -m url_guard_bot

package:
	python scripts/build_release.py
