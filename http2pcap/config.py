"""Deployment-time configuration, overridable via environment variables.

Values are read once at import time; in the container deployment model the
environment is fixed at container start, so no live reload is needed.
"""

import os


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None


# Generating a pcap costs ~9s CPU and ~16x memory per MB of input, so cap the
# request body hard. Bulk generation belongs on the CLI, not this API.
MAX_BODY_BYTES = _int_env("HTTP2PCAP_MAX_BODY_BYTES", 256 * 1024)

# Concurrent connections admitted by uvicorn; the rest queue.
LIMIT_CONCURRENCY = _int_env("HTTP2PCAP_LIMIT_CONCURRENCY", 3)

# TCP segment size used when splitting payloads into packets.
DEFAULT_MSS = _int_env("HTTP2PCAP_MSS", 1460)
