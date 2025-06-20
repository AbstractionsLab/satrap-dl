"""
SATRAP V0.2 (Alpha)
Semi-Automated Threat Reconnaissance and Analysis Platform 

Open-source, cross-platform software for computer-aided analysis of cyber threat intelligence (CTI) leveraging automated reasoning.
"""
import os
import tomllib


__project__ = "SATRAP"
__description__ = "Cyber threat Intelligence powered by automated reasoning."

# Load settings from pyproject.toml if it exists
_toml_file = "pyproject.toml"
_toml_config = {}

if os.path.exists(_toml_file):
    with open(_toml_file, "rb") as f:
        _toml_config = tomllib.load(f)

__version__ = _toml_config.get("tool", {}).get("poetry", {}).get("version", "_undefined")
__description__ = _toml_config.get("tool", {}).get("poetry", {}).get("description", __description__)
     
PROJ_NAME = f"{__project__} v{__version__}"
