"""Lightweight local timing helpers (not published as benchmarks)."""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager

logger = logging.getLogger(__name__)


@contextmanager
def log_duration(operation: str) -> Iterator[dict[str, float]]:
    """Record elapsed milliseconds for a local operation."""
    started = time.perf_counter()
    bucket: dict[str, float] = {}
    try:
        yield bucket
    finally:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        bucket["elapsed_ms"] = elapsed_ms
        logger.debug("timing | %s | %.2f ms (local measurement only)", operation, elapsed_ms)
