"""Configuration utility — loads .vibeaudit.yml + env vars."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

import yaml


_DEFAULT_CONFIG: Dict[str, Any] = {
    "mode": "full",
    "threshold": 60,
    "severity_filter": [],
    "exclude": ["node_modules/", ".venv/", "__pycache__/"],
    "llm": {
        "provider": "openai",
        "token_budget": 5000,
    },
}


def load_config(repo_path: str | None = None) -> Dict[str, Any]:
    """Load config from .vibeaudit.yml, falling back to defaults.

    Priority: env vars > yaml file > defaults.
    """
    config = _DEFAULT_CONFIG.copy()

    # Try to load YAML
    search = Path(repo_path) if repo_path else Path.cwd()
    yml_path = search / ".vibeaudit.yml"
    if yml_path.exists():
        with open(yml_path) as f:
            user_cfg = yaml.safe_load(f) or {}
        _deep_merge(config, user_cfg)

    # Env var overrides
    if os.environ.get("VIBE_AUDIT_API_KEY"):
        config.setdefault("llm", {})["api_key"] = os.environ["VIBE_AUDIT_API_KEY"]
    if os.environ.get("VIBE_AUDIT_PROVIDER"):
        config.setdefault("llm", {})["provider"] = os.environ["VIBE_AUDIT_PROVIDER"]
    if os.environ.get("VIBE_AUDIT_TOKEN_BUDGET"):
        config.setdefault("llm", {})["token_budget"] = int(
            os.environ["VIBE_AUDIT_TOKEN_BUDGET"]
        )

    return config


def _deep_merge(base: dict, override: dict) -> None:
    """Recursively merge *override* into *base* in-place."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
