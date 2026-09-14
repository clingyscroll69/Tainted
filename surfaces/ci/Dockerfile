# Tainted CI runner.
#
# The build context is the REPOSITORY ROOT, because the core engine lives outside this folder
# and every install here needs it. Two callers both satisfy that:
#
#   * the GitHub Action — `action.yml` sits at the repo root and names this file, and a Docker
#     action's build context is the directory holding its `action.yml`;
#   * by hand — `docker build -f surfaces/ci/Dockerfile -t tainted-ci .` from the root.
#
# `tests/test_action_contract.py` checks every COPY below against that context.
FROM python:3.12-slim

WORKDIR /app

# `git` and `gh` are here for one feature and only one: TAINTED_FIX, which branches, commits the
# deterministic fixes, pushes, and opens the pull request (`tainted_ci/pull_request.py` shells
# out to both). A slim base has neither, so before this the feature had a tutorial lesson, a
# README section, and a first step that failed every time. `gh` is not in Debian bookworm, hence
# the vendor repository.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends git ca-certificates curl gnupg; \
    mkdir -p -m 755 /etc/apt/keyrings; \
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
      -o /etc/apt/keyrings/githubcli-archive-keyring.gpg; \
    chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg; \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      > /etc/apt/sources.list.d/github-cli.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends gh; \
    apt-get purge -y --auto-remove gnupg; \
    rm -rf /var/lib/apt/lists/*

# Core engine (copied verbatim from the repo root) + this surface.
COPY pyproject.toml README.md /app/
COPY tainted /app/tainted
COPY surfaces/ci /app/surfaces/ci

RUN pip install --no-cache-dir -e . && pip install --no-cache-dir -e surfaces/ci

# The checkout GitHub mounts is owned by a different uid than this container's root, and git
# refuses to operate in a repository it thinks belongs to someone else. That refusal surfaces as
# an opaque `git checkout -b` failure inside the auto-fix step.
RUN git config --system --add safe.directory '*'

# The runner reads all configuration from the environment (see entrypoint.py).
ENTRYPOINT ["tainted-ci"]
