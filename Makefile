# Shortcuts for working on the sandbox itself. The checks are the ones CI
# runs (.github/workflows/ci.yml), keep the two in step.

# A Python tool from PATH, else run by uvx or pipx, as CI does
python_tool = $(or $(shell command -v $(1) 2>/dev/null),$(if \
	$(shell command -v uvx 2>/dev/null),uvx $(1),pipx run $(1)))

PYTHON ?= python3
RUFF ?= $(call python_tool,ruff)
MYPY ?= $(call python_tool,mypy)
SHELLCHECK ?= shellcheck

LAUNCHER := bin/claude-docker
PYTHON_SOURCES := $(LAUNCHER) claude_sandbox test docker/update-pins.py \
	docker/features/excalidraw/excalidraw-export
SHELL_SOURCES := bin/claude-statusline test/smoke/run.sh \
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
	$(RUFF) check $(PYTHON_SOURCES)
	$(RUFF) format --check $(PYTHON_SOURCES)
	$(SHELLCHECK) $(SHELL_SOURCES)

.PHONY: types
types: ## mypy
	$(MYPY) claude_sandbox $(LAUNCHER)

.PHONY: test
test: ## The unit tests, without Docker. One topic: make test K=trace
	$(PYTHON) test/launcher_test.py $(if $(K),-k $(K))

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

.PHONY: upgrade
upgrade: pins rebuild ## Refresh the pins, then rebuild the image
