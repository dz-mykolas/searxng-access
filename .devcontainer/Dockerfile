FROM mcr.microsoft.com/devcontainers/base:bookworm

COPY --from=ghcr.io/astral-sh/uv:0.11.31 /uv /uvx /bin/

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-venv \
        build-essential \
        libffi-dev \
        libssl-dev \
        libxml2-dev \
        libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*
