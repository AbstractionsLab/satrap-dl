"""
Configuration loading utilities for DECIPHER.

Provides centralized YAML configuration loading with caching and fallback support.
"""

from functools import lru_cache
from pathlib import Path
from typing import Any
import yaml


@lru_cache(maxsize=16)
def _load_yaml_with_mtime(path: str, mtime: float) -> dict[str, Any]:
    """
    Internal cached YAML loader. The 'mtime' argument is added so that
    the file's modification time is included in the cache key (path, mtime),
    which determines when the cached value should be invalidated.

    Raises:
        YAMLError: If the YAML file cannot be parsed.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            return config if config is not None else {}
    except yaml.YAMLError as e:
        raise yaml.YAMLError(f"Failed to parse YAML '{path}': {e}") from e


def load_yaml_file(filepath: Path) -> dict[str, Any]:
    """
    Load a YAML configuration file.

    Uses mtime-based caching: the file is re-read only when it has been
    modified since the last load, otherwise the cached dict is returned.

    Args:
        filepath: Absolute path to the YAML file.

    Returns:
        Configuration dictionary loaded from the YAML file.

    Raises:
        FileNotFoundError: If the file does not exist.
        yaml.YAMLError: If the YAML file cannot be parsed.
    """
    if not filepath.exists():
        raise FileNotFoundError(f"Configuration file not found: {filepath}")

    # last modification time of the file
    mtime = filepath.stat().st_mtime
    return _load_yaml_with_mtime(str(filepath), mtime)


def reload_config() -> None:
    """
    Clear the YAML cache, forcing all files to be reloaded on next access.
    """
    _load_yaml_with_mtime.cache_clear()
