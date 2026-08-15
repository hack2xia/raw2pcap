# syntax=docker/dockerfile:1

# ---- builder: resolve deps into a venv (uv binary stays in this stage) ----
FROM ghcr.io/astral-sh/uv:python3.11-bookworm-slim AS builder

WORKDIR /app

# Copy dependency manifests first for better layer caching.
# README.md and LICENSE are needed by hatchling to build the project itself.
COPY pyproject.toml uv.lock .python-version README.md LICENSE ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project --no-dev

# Copy source and install the project itself.
COPY raw2pcap ./raw2pcap
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev

# ---- runtime: plain slim Python, only the venv and app come over ----
FROM python:3.11-slim

WORKDIR /app
COPY --from=builder /app/.venv ./.venv
COPY raw2pcap ./raw2pcap

ENV PATH="/app/.venv/bin:$PATH"

EXPOSE 5000

# The app only synthesizes packets in memory - no NET_ADMIN or root caps needed.
CMD ["raw2pcap", "serve", "--host", "0.0.0.0", "--port", "5000"]
