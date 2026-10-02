"""Safe client-facing error helpers. Never include stack traces or secrets."""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

_SECRET_KEYS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "private_key",
    "credential",
)

_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s]+|/(?:home|Users|root)/[^\s]+")


def sanitize_public_message(message: str, *, fallback: str = "Request failed") -> str:
    """Strip filesystem paths and obvious secret-like fragments from a message."""
    text = str(message or "").strip() or fallback
    lowered = text.lower()
    if any(key in lowered for key in _SECRET_KEYS):
        return fallback
    text = _PATH_RE.sub("[path]", text)
    if "traceback" in lowered or "file \"" in lowered:
        return fallback
    return text[:500]


def looks_like_secret_key(name: str) -> bool:
    lowered = str(name).lower()
    return any(key in lowered for key in _SECRET_KEYS)


def filter_public_mapping(payload: dict[str, Any]) -> dict[str, Any]:
    """Drop keys that look like secrets from an API payload."""
    return {k: v for k, v in payload.items() if not looks_like_secret_key(str(k))}
