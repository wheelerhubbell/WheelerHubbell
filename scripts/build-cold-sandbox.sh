#!/usr/bin/env bash
set -euo pipefail
# Generic Python runtime only. No WHP files, fixture keys, URLs or application config enter it.
context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT
cat > "$context/Dockerfile" <<'DOCKER'
FROM python:3.13-slim-bookworm
RUN pip install --no-cache-dir cryptography==46.0.4 jsonschema==4.26.0
ENV PYTHONDONTWRITEBYTECODE=1
USER 65534:65534
DOCKER
docker build --pull -t cold-python-crypto:1 "$context"
docker image inspect cold-python-crypto:1 --format '{{.Id}}'
