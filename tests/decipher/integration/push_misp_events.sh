#!/bin/bash

# This script runs `events_simulator.py` to create events in a MISP instance
# To delete the python environment after testing, run: rm -rf .venv-pymisp

set -e

# Update with your settings
MISP_URL="https://localhost:50001"
MISP_API_KEY=""


VENV_DIR=".venv-pymisp"

if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install --quiet pymisp
fi

"$VENV_DIR/bin/python" events_simulator.py --url "$MISP_URL" --api-key "$MISP_API_KEY" --push
