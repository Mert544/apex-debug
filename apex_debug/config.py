"""Configuration loader for Apex Debug.

Hierarchy (highest precedence first):
1. CLI flags
2. .apex-debug.yaml in project root
3. ~/.apex-debug/config.yaml
4. config/default.yaml (bundled defaults)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml

from apex_debug.core.session import SessionConfig

BUNDLED_CONFIG = Path(__file__).parent.parent / "config" / "default.yaml"


def _load_yaml(path: Path) -> Optional[dict[str, Any]]:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return None


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(project_root: Optional[Path] = None) -> dict[str, Any]:
    """Load configuration from all sources.

    Args:
        project_root: Project directory to search for .apex-debug.yaml

    Returns:
        Merged configuration dictionary
    """
    # 1. Bundled defaults
    config = _load_yaml(BUNDLED_CONFIG) or {}

    # 2. User global config
    user_config_path = Path.home() / ".apex-debug" / "config.yaml"
    user_config = _load_yaml(user_config_path)
    if user_config:
        config = _deep_merge(config, user_config)

    # 3. Project-local config
    if project_root:
        local_config_path = project_root / ".apex-debug.yaml"
        local_config = _load_yaml(local_config_path)
        if local_config:
            config = _deep_merge(config, local_config)

    return config


def apply_config_to_session(config: dict[str, Any], session_config: SessionConfig) -> SessionConfig:
    """Apply loaded config dict to a SessionConfig instance.

    Args:
        config: Loaded configuration dictionary
        session_config: SessionConfig to modify

    Returns:
        Updated SessionConfig
    """
    patterns = config.get("patterns", {})
    if patterns.get("security") is not None:
        session_config.patterns_security = patterns["security"]
    if patterns.get("correctness") is not None:
        session_config.patterns_correctness = patterns["correctness"]
    if patterns.get("performance") is not None:
        session_config.patterns_performance = patterns["performance"]
    if patterns.get("style") is not None:
        session_config.patterns_style = patterns["style"]

    severity = config.get("severity", {})
    if severity.get("min_report"):
        session_config.min_severity = severity["min_report"]

    kb = config.get("knowledge_base", {})
    if kb.get("enabled") is not None:
        pass  # KB always on unless --no-kb
    if kb.get("path"):
        session_config.knowledge_base_path = kb["path"]

    return session_config


def find_project_root(start: Path) -> Path:
    """Find project root by looking for .apex-debug.yaml or .git.

    Args:
        start: Starting directory or file

    Returns:
        Discovered project root (defaults to start's parent)
    """
    if start.is_file():
        start = start.parent

    current = start.resolve()
    for _ in range(10):  # Limit search depth
        if (current / ".apex-debug.yaml").exists():
            return current
        if (current / ".git").exists():
            return current
        if (current / "pyproject.toml").exists():
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent

    return start.resolve()
