"""Application paths and runtime configuration."""

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "data" / "netpulse.db"
DEFAULT_SETTINGS_PATH = PROJECT_ROOT / "data" / "settings.json"


def ensure_runtime_directories() -> None:
    """Create directories used for mutable runtime data."""
    DEFAULT_DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)


def load_language() -> str:
    """Load the persisted UI language, falling back safely to English."""
    try:
        data = json.loads(DEFAULT_SETTINGS_PATH.read_text(encoding="utf-8"))
        return data.get("language", "en") if data.get("language") in {"en", "es"} else "en"
    except (OSError, ValueError, TypeError):
        return "en"


def save_language(language: str) -> None:
    ensure_runtime_directories()
    current = {}
    try:
        current = json.loads(DEFAULT_SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        pass
    current["language"] = language if language in {"en", "es"} else "en"
    DEFAULT_SETTINGS_PATH.write_text(
        json.dumps(current, indent=2, ensure_ascii=False), encoding="utf-8"
    )
