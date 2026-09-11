# Five services, three demos, one test suite. `make` on its own lists the targets.
#
# Everything here is a thin wrapper over a command you could type yourself. If a
# target ever does something you cannot see, that is a bug in this file.

PY        := .venv/bin/python
COMPOSE   := docker compose
DEMO_FLAGS ?=

# Bare-metal overrides. In compose the services find each other by service name;
# run bare, they are all on localhost. ISSUER_URL is both the `iss` claim and the
# address of the IdP, so it has to match everywhere or every audience check fails.
DEV_ENV := \
	ISSUER_URL=http://localhost:8081 \
	CONTRACTS_API_URL=http://localhost:8091 \
	MCP_CONTRACTS_URL=http://localhost:8092/mcp \
	MCP_TICKETS_URL=http://localhost:8093/mcp \
	MODEL_BASE_URL=$${MODEL_BASE_URL:-http://localhost:11434/v1} \
	PYTHONUNBUFFERED=1

.DEFAULT_GOAL := help
.PHONY: help up down logs dev demo test fmt diagrams

help: ## List targets
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-8s %s\n", $$1, $$2}'

up: ## Build and start the whole stack, waiting for every healthcheck
	$(COMPOSE) up -d --build --wait
	@echo
	@echo "  gateway   http://localhost:8080"
	@echo "  idp       http://localhost:8081"
	@echo "  audit     http://localhost:8080/audit"
	@echo
	@echo "  next: make demo"

down: ## Stop the stack and remove its network and volumes
	$(COMPOSE) down -v --remove-orphans

logs: ## Follow logs from all five services
	$(COMPOSE) logs -f --tail=50

dev: ## Run all five services bare on the host with the repo venv, no Docker
	@test -x $(PY) || { echo "no venv: python -m venv .venv && .venv/bin/pip install -r services/gateway/requirements.txt ..."; exit 1; }
	@echo "Ctrl-C stops all five."
	@set -e; \
	start_service() { \
	  entry=$$(ls services/$$1/main.py services/$$1/app.py services/$$1/server.py 2>/dev/null | head -n1); \
	  if [ -z "$$entry" ]; then echo "no entrypoint found in services/$$1"; exit 1; fi; \
	  echo "  starting $$1 ($$entry)"; \
	  env PYTHONPATH=$(CURDIR) $(DEV_ENV) $(PY) $$entry & \
	}; \
	trap 'kill 0' INT TERM; \
	start_service idp; \
	sleep 2; \
	start_service contracts_api; \
	start_service mcp_contracts; \
	start_service mcp_tickets; \
	sleep 2; \
	start_service gateway; \
	wait

demo: ## Run the three demos in order (make demo DEMO_FLAGS=--auto-flip for one take)
	$(PY) demos/01_confused_deputy.py
	$(PY) demos/02_wrong_audience.py $(DEMO_FLAGS)
	$(PY) demos/03_injection.py

test: ## Start the stack with the deterministic model stub and run the property tests
	MODEL_BACKEND=replay $(COMPOSE) up -d --build --wait
	MODEL_BACKEND=replay $(PY) -m pytest -q tests/

fmt: ## Format and lint if ruff is installed, syntax-check either way
	@if $(PY) -m ruff --version >/dev/null 2>&1; then \
	  $(PY) -m ruff format common demos services tests; \
	  $(PY) -m ruff check --fix common demos services tests; \
	else \
	  echo "ruff not installed (.venv/bin/pip install ruff); syntax check only"; \
	fi
	@$(PY) -m compileall -q common demos services tests >/dev/null && echo "syntax ok"

diagrams: ## Regenerate docs/diagrams/*.svg from the mermaid source in the markdown
	@./scripts/render-diagrams.sh
