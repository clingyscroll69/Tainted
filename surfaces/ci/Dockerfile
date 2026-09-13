# Tainted CI runner. Build context is the REPO ROOT (so the core is included):
#   docker build -f surfaces/ci/Dockerfile -t tainted-ci .
FROM python:3.12-slim

WORKDIR /app

# Core engine (copied verbatim from the repo root) + this surface.
COPY pyproject.toml README.md /app/
COPY tainted /app/tainted
COPY surfaces/ci /app/surfaces/ci

RUN pip install --no-cache-dir -e . && pip install --no-cache-dir -e surfaces/ci

# The runner reads all configuration from the environment (see entrypoint.py).
ENTRYPOINT ["tainted-ci"]
