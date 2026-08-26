"""Persistent logging for the desktop application.

Flet Desktop detaches from a console, so anything written to ``stderr`` is
invisible in practice. Routing the application logger to a rotating file keeps
the exceptions that the update loop and the scan workers already report.
"""

import logging
import logging.handlers
import os
from pathlib import Path

from netpulse.config import DEFAULT_LOG_PATH, ensure_runtime_directories

MAX_BYTES = 2 * 1024 * 1024
BACKUP_COUNT = 3
_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_configured = False


def _resolve_level() -> int:
    """Read NETPULSE_LOG_LEVEL, falling back to INFO for unknown values."""
    name = os.getenv("NETPULSE_LOG_LEVEL", "INFO").upper()
    level = logging.getLevelName(name)
    return level if isinstance(level, int) else logging.INFO


def configure_logging(path: Path | None = None, force: bool = False) -> Path | None:
    """Attach a rotating file handler to the ``netpulse`` logger once.

    Returns the active log path, or ``None`` when the file cannot be opened —
    logging must never prevent the application from starting.
    """
    global _configured
    if _configured and not force:
        return DEFAULT_LOG_PATH
    target = Path(path) if path is not None else DEFAULT_LOG_PATH
    logger = logging.getLogger("netpulse")
    logger.setLevel(_resolve_level())
    logger.propagate = False
    if force:
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()
    try:
        ensure_runtime_directories()
        target.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            target, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8",
        )
    except OSError:
        _configured = True
        return None
    handler.setFormatter(logging.Formatter(_FORMAT))
    logger.addHandler(handler)
    _configured = True
    return target
