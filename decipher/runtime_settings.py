from dataclasses import dataclass, field, fields
from typing import Any

from yaml import YAMLError

from decipher.settings import RUNTIME_CONFIG_PATH
from decipher.commons.config_loader import load_yaml_file
from decipher.commons.log_utils import get_logger

logger = get_logger(__name__)


@dataclass
class RuntimeSettings:
    enable_misp_search: bool = False
    enable_case_creation: bool = False
    misp_search: dict[str, Any] = field(default_factory=dict)
    priority_thresholds: dict[str, float] = field(
        default_factory=lambda: {"severe": 0.85, "high": 0.6, "medium": 0.4, "low": 0.2}
    )


def load_decipher_runtime_cfg() -> RuntimeSettings:
    """Load and return a DecipherSettings object, applying environment overrides."""

    try:
        settings_data = load_yaml_file(RUNTIME_CONFIG_PATH)
    except FileNotFoundError:
        logger.warning(
            f"File not found at {RUNTIME_CONFIG_PATH}. Running analysis with defaults."
        )
        settings_data = {}
    except YAMLError as e:
        logger.error(f"Invalid file {RUNTIME_CONFIG_PATH}. Verify the YAML syntax: {e}")
        raise

    analysis_cfg = settings_data.get("analysis", {})
    all_data = {**analysis_cfg, **settings_data}

    # Only include fields of RuntimeSettings specified in the config file
    # this allows for the default values in the dataclass to be used for not specified settings
    valid_fields = {f.name for f in fields(RuntimeSettings)}
    overrides = {
        k: v for k, v in all_data.items() if k in valid_fields and v is not None
    }

    return RuntimeSettings(**overrides)
