# Tainted website. Build context is the REPO ROOT (so the core is included):
#   docker build -f surfaces/website/Dockerfile -t tainted-web .
FROM python:3.12-slim

WORKDIR /app

# Playwright's browsers go somewhere every uid can read, because they are installed as root and
# the server does not run as root. Left at the default (~/.cache/ms-playwright) they land in
# root's home and the unprivileged process cannot see them — which fails at the first
# autodiscovery walk, not at build time.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

COPY pyproject.toml README.md /app/
COPY tainted /app/tainted
COPY surfaces/website /app/surfaces/website

# Core (with the dynamic extra for prove) + this surface.
RUN pip install --no-cache-dir -e ".[dynamic]" \
 && pip install --no-cache-dir -e surfaces/website

# The Python package is not the browser. `pip install playwright` installs a client for a
# Chromium that is not there yet, so `prove`'s discovery walk failed at runtime in the very
# image built to support it. `--with-deps` pulls the shared libraries Chromium needs on slim.
RUN playwright install --with-deps chromium \
 && chmod -R a+rX /ms-playwright \
 && rm -rf /var/lib/apt/lists/*

# `prove` executes untrusted, network-active exploits generated against a stranger's repository.
# Running that as uid 0 means a container escape and a process escape are the same event. The
# server needs no write access to anything it ships — checkouts go to /tmp — so it drops to an
# unprivileged user for good.
RUN useradd --create-home --uid 10001 tainted

# Fail closed on the one thing that cannot be inferred from a missing variable. Without this,
# a deployment whose sandbox is misconfigured quietly runs those exploits on its own metal and
# looks exactly like one that is working. `sandbox.py` has always said the production entrypoint
# sets it; this is the production entrypoint, and now it does.
#
# The bundled demo (`demo/demo`) contacts nothing and is exempt, so a container run with no
# further configuration still demonstrates the whole loop. A real `prove` needs
# TAINTED_SANDBOX_URL and TAINTED_SANDBOX_TOKEN — or TAINTED_REQUIRE_SANDBOX=0 to say out loud
# that you accept in-process execution.
ENV TAINTED_REQUIRE_SANDBOX=1 \
    TAINTED_CSP_ENFORCE=1 \
    HOST=0.0.0.0 \
    PORT=8000

USER tainted
EXPOSE 8000
WORKDIR /app/surfaces/website

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,os,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8000')+'/healthz',timeout=4).status==200 else 1)"

CMD ["tainted-web"]
