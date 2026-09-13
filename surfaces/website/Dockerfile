# Tainted website. Build context is the REPO ROOT (so the core is included):
#   docker build -f surfaces/website/Dockerfile -t tainted-web .
FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY tainted /app/tainted
COPY surfaces/website /app/surfaces/website

# Core (with the dynamic extra for prove) + this surface.
RUN pip install --no-cache-dir -e ".[dynamic]" \
 && pip install --no-cache-dir -e surfaces/website

ENV HOST=0.0.0.0 PORT=8000
EXPOSE 8000
WORKDIR /app/surfaces/website
CMD ["tainted-web"]
