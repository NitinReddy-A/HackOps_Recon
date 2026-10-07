# syntax=docker/dockerfile:1

# ---- Stage 1: build a wheel from the source ----
FROM python:3.12-slim AS build
WORKDIR /src
COPY . .
RUN python -m pip install --upgrade pip build \
    && python -m build --wheel --outdir /dist

# ---- Stage 2: tiny runtime image ----
FROM python:3.12-slim AS runtime

# Rampart's core has ZERO runtime dependencies (stdlib only), so the image
# stays small. Install only the built wheel.
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

# External scanners (nuclei / semgrep / nmap / trivy / testssl.sh) are OPTIONAL
# and are NOT bundled — the built-in oracles run with no external tools. To use
# the `--scanners` adapters, layer them into your own derived image, e.g.:
#   RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*
#   COPY --from=projectdiscovery/nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei

# Run as a non-root user.
RUN useradd --create-home --uid 10001 rampart
USER rampart
WORKDIR /work

ENTRYPOINT ["python", "-m", "rampart"]
CMD ["--help"]
