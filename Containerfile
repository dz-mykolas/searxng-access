# syntax=docker/dockerfile:1.7

ARG SEARXNG_IMAGE=docker.io/searxng/searxng:2026.7.19-6da6eee26

FROM ghcr.io/astral-sh/uv:0.11.31 AS uv

FROM docker.io/library/python:3.11-slim-bookworm AS plugin-builder
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /build
COPY LICENSE README.md pyproject.toml uv.lock ./
COPY src/ ./src/
RUN uv build --wheel --out-dir /dist

FROM ${SEARXNG_IMAGE}

ARG SEARXNG_IMAGE
LABEL org.opencontainers.image.description="SearXNG with token and browser-session access control" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/dz-mykolas/searxng-access" \
      org.opencontainers.image.title="SearXNG Access" \
      org.opencontainers.image.base.name="${SEARXNG_IMAGE}"

RUN --mount=from=uv,source=/uv,target=/tmp/uv \
    --mount=from=plugin-builder,source=/dist,target=/tmp/dist,ro \
    /tmp/uv pip install \
        --python /usr/local/searxng/.venv/bin/python \
        --no-cache \
        /tmp/dist/*.whl \
    && ln -s /usr/local/searxng/.venv/bin/searxng-access /usr/bin/searxng-access

COPY --chown=977:977 container/settings.template.yml /usr/local/searxng/settings.template.yml

ENV SEARXNG_ACCESS_DB=/var/cache/searxng/access.db

RUN /usr/local/searxng/.venv/bin/python -c \
    "from pathlib import Path; import yaml; from searxng_access.plugin import SXNGPlugin; cfg = yaml.safe_load(Path('/usr/local/searxng/settings.template.yml').read_text()); assert SXNGPlugin.id == 'searxng_access'; assert cfg['plugins']['searxng_access.plugin.SXNGPlugin']['active'] is True" \
    && test -x /usr/bin/searxng-access
