"""Application paths and runtime configuration."""

import json
from pathlib import Path
from typing import Any, Dict


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "data" / "netpulse.db"
DEFAULT_SETTINGS_PATH = PROJECT_ROOT / "data" / "settings.json"
DEFAULT_LOG_PATH = PROJECT_ROOT / "data" / "netpulse.log"

LANGUAGES = ("en", "es")
THEMES = ("netpulse", "midnight", "graphite", "black", "daylight", "paper")
LIGHT_THEMES = ("daylight", "paper")
# Green, amber and red carry state; offering them as accents made the chrome
# read as a permanent success or warning. Older choices map onto the survivors.
ACCENTS = ("cyan", "blue", "violet", "magenta", "slate")
LEGACY_ACCENTS = {"green": "cyan", "amber": "magenta", "purple": "violet"}
DENSITIES = ("compact", "standard", "comfortable")

DEFAULT_APPEARANCE = {"theme": "netpulse", "accent": "cyan", "density": "standard"}
DEFAULT_ALERTS = {"bandwidth_kbps": 0.0, "packets_per_second": 0.0}
# Zero keeps every session; the settings view exposes the supported presets.
DEFAULT_RETENTION_DAYS = 0


def ensure_runtime_directories() -> None:
    """Create directories used for mutable runtime data."""
    DEFAULT_DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)


def _read_settings() -> Dict[str, Any]:
    """Return the persisted settings document, or an empty one when unusable."""
    try:
        data = json.loads(DEFAULT_SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_settings(patch: Dict[str, Any]) -> None:
    """Merge *patch* into the settings document without dropping other keys."""
    ensure_runtime_directories()
    current = _read_settings()
    current.update(patch)
    DEFAULT_SETTINGS_PATH.write_text(
        json.dumps(current, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def load_language() -> str:
    """Load the persisted UI language, falling back safely to English."""
    language = _read_settings().get("language")
    return language if language in LANGUAGES else "en"


def save_language(language: str) -> None:
    _write_settings({"language": language if language in LANGUAGES else "en"})


def load_appearance() -> dict:
    """Load validated appearance preferences."""
    appearance = dict(DEFAULT_APPEARANCE)
    stored = _read_settings().get("appearance")
    if not isinstance(stored, dict):
        return appearance
    if stored.get("theme") in THEMES:
        appearance["theme"] = stored["theme"]
    accent = LEGACY_ACCENTS.get(stored.get("accent"), stored.get("accent"))
    if accent in ACCENTS:
        appearance["accent"] = accent
    if stored.get("density") in DENSITIES:
        appearance["density"] = stored["density"]
    return appearance


def save_appearance(theme: str, accent: str, density: str) -> None:
    _write_settings({"appearance": {
        "theme": theme if theme in THEMES else DEFAULT_APPEARANCE["theme"],
        "accent": (accent if accent in ACCENTS
                   else LEGACY_ACCENTS.get(accent, DEFAULT_APPEARANCE["accent"])),
        "density": density if density in DENSITIES else DEFAULT_APPEARANCE["density"],
    }})


def is_light_theme(theme: str) -> bool:
    """Report whether *theme* is rendered with a light background."""
    return theme in LIGHT_THEMES


def _positive_float(value: Any) -> float:
    """Coerce persisted JSON into a non-negative threshold."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return number if number > 0 else 0.0


def load_alerts() -> dict:
    """Load persisted traffic alert thresholds (0 disables an alert)."""
    stored = _read_settings().get("alerts")
    if not isinstance(stored, dict):
        return dict(DEFAULT_ALERTS)
    return {
        "bandwidth_kbps": _positive_float(stored.get("bandwidth_kbps")),
        "packets_per_second": _positive_float(stored.get("packets_per_second")),
    }


def save_alerts(bandwidth_kbps: float, packets_per_second: float) -> None:
    _write_settings({"alerts": {
        "bandwidth_kbps": _positive_float(bandwidth_kbps),
        "packets_per_second": _positive_float(packets_per_second),
    }})


def load_interface() -> str:
    """Load the persisted capture interface, defaulting to every adapter."""
    interface = _read_settings().get("interface")
    if not isinstance(interface, str) or not interface.strip():
        return "All"
    return interface.strip()


def save_interface(interface: str) -> None:
    name = (interface or "").strip() or "All"
    _write_settings({"interface": name})


def load_retention_days() -> int:
    """Load how many days of capture history to keep (0 keeps everything)."""
    try:
        days = int(_read_settings().get("retention_days", DEFAULT_RETENTION_DAYS))
    except (TypeError, ValueError):
        return DEFAULT_RETENTION_DAYS
    return days if days > 0 else 0


def save_retention_days(days: int) -> None:
    try:
        value = int(days)
    except (TypeError, ValueError):
        value = DEFAULT_RETENTION_DAYS
    _write_settings({"retention_days": max(0, value)})
