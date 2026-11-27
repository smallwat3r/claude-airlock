# Shortcuts for working on the sandbox itself. The checks are the ones CI
# runs (.github/workflows/ci.yml), keep the two in step. What ruff, mypy
# and pytest check, and by which rules, is in pyproject.toml.

# The tools and the Python they run on are uv's, at the versions of uv.lock
UV_RUN ?= uv run --locked
PYTHON ?= $(UV_RUN) python
RUFF ?= $(UV_RUN) ruff
MYPY ?= $(UV_RUN) mypy
PYTEST ?= $(UV_RUN) pytest
SHELLCHECK ?= shellcheck

LAUNCHER := bin/claude-airlock
SHELL_SOURCES := docker/squid-ask-helper.sh \
	test/smoke/run.sh \
	$(wildcard test/smoke/inside/*.sh)

.DEFAULT_GOAL := help

.PHONY: help
help: ## List the targets
	@awk 'BEGIN { FS = ":.*## " } /^[a-z-]+:.*## / \
		{ printf "  %-12s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: check
check: lint types test ## Everything CI checks but the image build

.PHONY: lint
lint: ## ruff, its formatter and shellcheck
	$(RUFF) check
	$(RUFF) format --check
	$(SHELLCHECK) $(SHELL_SOURCES)

.PHONY: types
types: ## mypy
	$(MYPY)

.PHONY: test
test: ## The unit tests, the Dockerfile of every feature among them, without Docker. One topic: make test K=trace
	$(PYTEST) $(if $(K),-k $(K))

.PHONY: smoke
smoke: ## The end-to-end test, on the host against a real Docker daemon
	test/smoke/run.sh

.PHONY: rebuild
rebuild: ## Rebuild the image from scratch, without the layer cache
	$(LAUNCHER) --rebuild

.PHONY: prune
prune: ## Delete all sandbox images but the current one
	$(LAUNCHER) --prune

.PHONY: dockerfile
dockerfile: ## Print the generated Dockerfile
	@$(LAUNCHER) --dockerfile

.PHONY: pins
pins: ## Refresh every pinned version, checksum and image digest
	docker/update-pins.py
	uv lock --upgrade

.PHONY: upgrade
upgrade: pins rebuild ## Refresh the pins, then rebuild the image
