# Shortcuts for working on the sandbox itself. The checks are the ones CI
# runs (.github/workflows/ci.yml), keep the two in step.

PYTHON ?= python3
RUFF ?= ruff
MYPY ?= mypy
SHELLCHECK ?= shellcheck

LAUNCHER := bin/claude-docker
PYTHON_SOURCES := $(LAUNCHER) claude_sandbox test docker/update-pins.py \
	docker/features/excalidraw/excalidraw-export
SHELL_SOURCES := bin/claude-statusline test/smoke-test.sh

.DEFAULT_GOAL := help

.PHONY: help
help: ## List the targets
	@awk 'BEGIN { FS = ":.*## " } /^[a-z-]+:.*## / \
		{ printf "  %-12s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: check
check: lint types test ## Everything CI checks but the image build

.PHONY: lint
lint: ## ruff and shellcheck
	$(RUFF) check $(PYTHON_SOURCES)
	$(SHELLCHECK) $(SHELL_SOURCES)

.PHONY: types
types: ## mypy
	$(MYPY) claude_sandbox $(LAUNCHER)

.PHONY: test
test: ## The unit tests, without Docker. One topic: make test K=trace
	$(PYTHON) test/launcher_test.py $(if $(K),-k $(K))

.PHONY: smoke
smoke: ## The end-to-end test, on the host against a real Docker daemon
	test/smoke-test.sh

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
