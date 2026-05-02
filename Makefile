# agentbox -- common development tasks.
#
# Thin wrappers around the underlying tools. Each target is one command;
# compose by chaining (e.g. `make lint typecheck`). Windows users without
# `make` can run the underlying commands directly.

PYTHON ?= python

.DEFAULT_GOAL := help
.PHONY: help test test-fast check build clean

help:
	@echo "agentbox dev targets:"
	@echo "  test        Full test suite (unit + Docker-backed e2e)"
	@echo "  test-fast   Skip e2e -- inner-loop iteration"
	@echo "  check       ruff check + pyright (always run together)"
	@echo "  build       Build wheel + sdist via uv (-> dist/)"
	@echo "  clean       Remove build artifacts and pyc caches"

test:
	$(PYTHON) -m unittest discover tests

test-fast:
	AGENTBOX_E2E_SKIP=1 $(PYTHON) -m unittest discover tests

check:
	$(PYTHON) -m ruff check src tests
	$(PYTHON) -m pyright

build:
	uv build

clean:
	rm -rf dist build *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
