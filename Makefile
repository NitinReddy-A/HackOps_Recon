# Rampart — developer convenience targets.
# Rampart's core is dependency-free stdlib Python; these just wrap the common
# commands. Use `python3` if `python` is not on your PATH.

PYTHON ?= python

.PHONY: install test bench demo demo-llm tools docker-build lint

install:  ## Install the package in editable mode
	$(PYTHON) -m pip install -e .

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

lint:  ## Byte-compile the package to catch syntax errors
	$(PYTHON) -m compileall rampart
