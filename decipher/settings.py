"""
DECIPHER settings and configuration paths.
"""

import os
from enum import Enum
from pathlib import Path
import sys

import yaml


# ----------------------------------------------
# Project directories
# ----------------------------------------------
DECIPHER_ROOT = Path(__file__).parent
PROJECT_ROOT = DECIPHER_ROOT.parent
CONFIG_DIR = PROJECT_ROOT / "config"
LOGS_DIR = PROJECT_ROOT / "logs" / "decipher"
FLOWINTEL_TEMPLATES_DIR = DECIPHER_ROOT / "casemanagement" / "flowintel_templates"

# Configuration file paths
DECIPHER_CONFIG_PATH = CONFIG_DIR / "decipher-settings.yaml"
RUNTIME_CONFIG_PATH = CONFIG_DIR / "decipher-runtime-cfg.yaml"
SCORING_CONFIG_PATH = CONFIG_DIR / "decipher-scoring-cfg.yaml"


# -----------------------------------------------------------
# DECIPHER API settings
# -----------------------------------------------------------
DEFAULT_API_HOST = "0.0.0.0"
DEFAULT_API_PORT = 8000
API_VERSION = "v0.1"
BASE_URL = os.path.join("/api", API_VERSION)


# ----------------------------------------------------------
# Names of analysis scenarios (kept here for consistency)
# ----------------------------------------------------------
class AnalysisScenario(Enum):
    SUSPICIOUS_LOGIN = "suspicious_login"


# ----------------------------------------------------------
# Static configuration from decipher-settings.yaml
# Requires restarting the server to update
# ----------------------------------------------------------

try:
    with open(DECIPHER_CONFIG_PATH, "r", encoding="utf-8") as f:
        settings_data = yaml.safe_load(f) or {}
except FileNotFoundError:
    print(
        f"WARNING: DECIPHER settings file not found at {DECIPHER_CONFIG_PATH}. Using defaults."
    )
    settings_data = {}
except Exception as e:
    print(
        f"Invalid DECIPHER settings file at {DECIPHER_CONFIG_PATH}. Please verify the YAML syntax."
    )
    print(f"[ERROR]: {e}")
    sys.exit(1)

_misp_cfg = settings_data.get("misp", {})
_flowintel_cfg = settings_data.get("flowintel", {})
_logging_cfg = settings_data.get("logging", {})

# MISP instance
MISP_URL: str = os.getenv("MISP_URL") or _misp_cfg.get("url", "")
MISP_API_KEY: str = os.getenv("MISP_API_KEY") or _misp_cfg.get("api_key", "")
MISP_VERIFY_SSL: bool = (
    os.getenv("MISP_VERIFY_SSL", str(_misp_cfg.get("verify_ssl", False))).lower()
    == "true"
)
try:
    MISP_TIMEOUT: int = int(
        os.getenv("MISP_TIMEOUT", str(_misp_cfg.get("timeout", "5")))
    )
except ValueError:
    MISP_TIMEOUT: int = 5

# Flowintel instance
_flowint_url: str = _flowintel_cfg.get("base_url", "").rstrip("/api")
FLOWINTEL_CASE_URL: str = _flowintel_cfg.get("case_url", _flowint_url) + "/case"

# Logging
LOG_LEVEL: str = _logging_cfg.get("level", "info")
ENABLE_FILE_LOGGING: bool = _logging_cfg.get("enable_file_logging", False)
