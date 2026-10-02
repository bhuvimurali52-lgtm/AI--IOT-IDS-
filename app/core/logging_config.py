"""Centralized logging configuration for the IoT IDS application."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

_SECRET_FRAGMENTS = (
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "token=",
    "authorization",
    "private_key",
)


class _RedactFilter(logging.Filter):
    """Drop or redact log records that appear to contain secrets."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage().lower()
        except Exception:  # noqa: BLE001
            return True
        if any(frag in message for frag in _SECRET_FRAGMENTS):
            record.msg = "[redacted log record]"
            record.args = ()
        return True


def setup_logging(log_level: str = "INFO", log_dir: Path | str = "logs") -> None:
    """Configure application-wide logging to console and rotating file."""
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    level = getattr(logging, str(log_level).upper(), logging.INFO)
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    if root_logger.handlers:
        root_logger.handlers.clear()

    redactor = _RedactFilter()

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(redactor)
    root_logger.addHandler(console_handler)

    file_handler = RotatingFileHandler(
        log_path / "iot_ids.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    file_handler.addFilter(redactor)
    root_logger.addHandler(file_handler)

    logging.getLogger(__name__).debug("Logging configured at %s", str(log_level).upper())
