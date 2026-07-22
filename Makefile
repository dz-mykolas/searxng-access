SEARXNG := .searxng
SEARXNG_REF := 6da6eee265daeb4a62ab638d6921522bf405de69
SEARXNG_PYTHON := $(SEARXNG)/local/py3/bin/python
PLUGIN_PATH := $(CURDIR)/src
SETTINGS := $(CURDIR)/dev/settings.yml
ACCESS_DB ?= $(CURDIR)/dev/access.db
DEV_TOKEN ?= development-token

.PHONY: setup test test-integration lint format run clean

setup:
	@if ! test -d $(SEARXNG)/.git; then \
		git init $(SEARXNG); \
		git -C $(SEARXNG) remote add origin https://github.com/searxng/searxng.git; \
	fi
	git -C $(SEARXNG) fetch --depth 1 origin $(SEARXNG_REF)
	git -C $(SEARXNG) checkout --detach $(SEARXNG_REF)
	$(MAKE) -C $(SEARXNG) install
	uv sync --locked

test:
	uv run pytest tests/unit

test-integration:
	PYTHONPATH="$(PLUGIN_PATH)" \
	SEARXNG_SETTINGS_PATH="$(SETTINGS)" \
	$(SEARXNG_PYTHON) -m unittest discover -s tests/integration -v

lint:
	uv run ruff check src tests

format:
	uv run ruff check --fix src tests
	uv run ruff format src tests

run:
	PYTHONPATH="$(PLUGIN_PATH)" \
	SEARXNG_SETTINGS_PATH="$(SETTINGS)" \
	SEARXNG_ACCESS_DB="$(ACCESS_DB)" \
	SEARXNG_ACCESS_DEV_TOKEN="$(DEV_TOKEN)" \
	SEARXNG_ACCESS_SECURE_COOKIE="false" \
	$(MAKE) -C $(SEARXNG) run

clean:
	rm -rf .coverage .pytest_cache .ruff_cache
