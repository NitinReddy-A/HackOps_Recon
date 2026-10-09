# Rampart — developer convenience targets.
# Rampart's core is dependency-free stdlib Python; these just wrap the common
# commands. Use `python3` if `python` is not on your PATH.

PYTHON ?= python

.PHONY: install dev test bench demo demo-llm tools docker-build lint format check

install:  ## Install the package in editable mode
	$(PYTHON) -m pip install -e .

dev:  ## Install with dev tools (pytest, ruff, pre-commit) and set up hooks
	$(PYTHON) -m pip install -e ".[dev]"
	pre-commit install

test:  ## Run the test suite
	$(PYTHON) -m pytest

bench:  ## Run the reliability benchmark (nonzero exit on FP/FN)
	$(PYTHON) benchmarks/run_benchmark.py

demo:  ## Run the local web/API demo end-to-end
	$(PYTHON) scripts/demo.py --no-open

demo-llm:  ## Run the local LLM (OWASP LLM Top 10) demo
	$(PYTHON) scripts/demo.py --llm --no-open

tools:  ## Show which external OSS scanners are installed (doctor)
	$(PYTHON) -m rampart tools

docker-build:  ## Build the Docker image
	docker build -t rampart:local .

lint:  ## Lint with ruff
	$(PYTHON) -m ruff check .

format:  ## Auto-format with ruff
	$(PYTHON) -m ruff format .

check:  ## Everything CI runs: lint + format check + tests + benchmark
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m pytest -q
	$(PYTHON) benchmarks/run_benchmark.py
