include ../Makefile

.PHONY: test

test:
	uv run pytest tests/unit -v --cov=utils --cov=validation --cov=tools --cov-report=term-missing --cov-fail-under=100
