"""Built-in theme presets for HTML security reports.

Themes are dictionaries of CSS variable overrides that control the look-and-feel
of the generated HTML report.  Users can pass a preset name (``"dark"``,
``"light"``, ``"corporate"``) or supply their own dictionary to override
individual values.
"""

from typing import Any, Dict, Optional, Union
import copy
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default dark theme  (matches the original report.html `:root` values)
# ---------------------------------------------------------------------------
DEFAULT_THEME = {
    "name": "dark",
    "css_vars": {
        "--bg-dark": "#0d1117",
        "--bg-card": "#161b22",
        "--text-primary": "#f0f6fc",
        "--text-secondary": "#8b949e",
        "--accent-purple": "#a855f7",
        "--accent-pink": "#ec4899",
        "--critical": "#f85149",
        "--high": "#f97316",
        "--medium": "#eab308",
        "--low": "#22c55e",
        "--info": "#3b82f6",
    },
    "logo_url": "",
    "logo_text": "🐱",
    "company_name": "",
}

# ---------------------------------------------------------------------------
# Light theme
# ---------------------------------------------------------------------------
LIGHT_THEME = {
    "name": "light",
    "css_vars": {
        "--bg-dark": "#f8f9fa",
        "--bg-card": "#ffffff",
        "--text-primary": "#1a1a2e",
        "--text-secondary": "#6c757d",
        "--accent-purple": "#7c3aed",
        "--accent-pink": "#db2777",
        "--critical": "#dc2626",
        "--high": "#ea580c",
        "--medium": "#ca8a04",
        "--low": "#16a34a",
        "--info": "#2563eb",
    },
    "logo_url": "",
    "logo_text": "🐱",
    "company_name": "",
}

# ---------------------------------------------------------------------------
# Corporate theme  (muted blue-grey)
# ---------------------------------------------------------------------------
CORPORATE_THEME = {
    "name": "corporate",
    "css_vars": {
        "--bg-dark": "#1e293b",
        "--bg-card": "#283548",
        "--text-primary": "#e2e8f0",
        "--text-secondary": "#94a3b8",
        "--accent-purple": "#6366f1",
        "--accent-pink": "#8b5cf6",
        "--critical": "#ef4444",
        "--high": "#f97316",
        "--medium": "#eab308",
        "--low": "#22c55e",
        "--info": "#3b82f6",
    },
    "logo_url": "",
    "logo_text": "🛡️",
    "company_name": "",
}

_PRESETS = {
    "dark": DEFAULT_THEME,
    "light": LIGHT_THEME,
    "corporate": CORPORATE_THEME,
}


def get_theme(
    theme_config: Optional[Union[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Resolve a theme configuration into a complete theme dictionary.

    Args:
        theme_config: One of:
            - ``None`` — returns the default dark theme.
            - A preset name string (``"dark"``, ``"light"``, ``"corporate"``).
            - A dictionary with optional keys ``"name"``, ``"css_vars"``,
              ``"logo_url"``, ``"logo_text"``, ``"company_name"``.  If a
              ``"name"`` key is present and matches a preset, unspecified
              keys are filled from that preset; otherwise the dark theme is
              used as the base.

    Returns:
        A fully resolved theme dictionary.
    """
    if theme_config is None:
        return copy.deepcopy(DEFAULT_THEME)

    if isinstance(theme_config, str):
        preset = _PRESETS.get(theme_config.lower())
        if preset is None:
            logger.warning(
                "Unknown theme preset '%s', falling back to dark theme.",
                theme_config,
            )
            return copy.deepcopy(DEFAULT_THEME)
        return copy.deepcopy(preset)

    if not isinstance(theme_config, dict):
        logger.warning(
            "Invalid theme_config type %s, falling back to dark theme.",
            type(theme_config).__name__,
        )
        return copy.deepcopy(DEFAULT_THEME)

    # Use the named base if provided, otherwise default
    base_name = theme_config.get("name", "dark")
    base = copy.deepcopy(_PRESETS.get(base_name, DEFAULT_THEME))

    # Merge top-level scalar keys
    for key in ("logo_url", "logo_text", "company_name", "name"):
        if key in theme_config:
            base[key] = theme_config[key]

    # Merge CSS variable overrides
    user_css = theme_config.get("css_vars", {})
    if isinstance(user_css, dict):
        base["css_vars"].update(user_css)

    # Also allow shorthand keys without the -- prefix mapping
    _SHORTHAND = {
        "primary_color": "--accent-purple",
        "secondary_color": "--accent-pink",
        "bg_color": "--bg-dark",
        "card_color": "--bg-card",
        "text_color": "--text-primary",
    }
    for shorthand, css_var in _SHORTHAND.items():
        if shorthand in theme_config:
            base["css_vars"][css_var] = theme_config[shorthand]

    return base
