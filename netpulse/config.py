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


def load_appearance() -> dict:
    """Load validated appearance preferences."""
    defaults = {"theme": "netpulse", "accent": "cyan", "density": "standard"}
    try:
        data = json.loads(DEFAULT_SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return defaults
    appearance = data.get("appearance", {})
    if appearance.get("theme") in {"netpulse", "midnight", "graphite", "black"}:
        defaults["theme"] = appearance["theme"]
    if appearance.get("accent") in {"cyan", "blue", "green", "purple", "amber"}:
        defaults["accent"] = appearance["accent"]
    if appearance.get("density") in {"compact", "standard", "comfortable"}:
        defaults["density"] = appearance["density"]
    return defaults


def save_appearance(theme: str, accent: str, density: str) -> None:
    ensure_runtime_directories()
    current = {}
    try:
        current = json.loads(DEFAULT_SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        pass
    current["appearance"] = {
        "theme": theme if theme in {"netpulse", "midnight", "graphite", "black"} else "netpulse",
        "accent": accent if accent in {"cyan", "blue", "green", "purple", "amber"} else "cyan",
        "density": density if density in {"compact", "standard", "comfortable"} else "standard",
    }
    DEFAULT_SETTINGS_PATH.write_text(
        json.dumps(current, indent=2, ensure_ascii=False), encoding="utf-8"
    )
