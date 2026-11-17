#!/usr/bin/env bash
# Validates the configuration of DECIPHER.
#
# The script runs a Python program inside the DECIPHER API container (docker exec).
# This program checks that the values set in config/*.yaml
# reach and authenticate to MISP and Flowintel instances.
#
# The script does not:
#   - Modify files, services or containers.
#   - Print API keys or take secrets as arguments.
#
# To validate integration with RADAR, see docs/manual/decipher/radar-integration.md.

set -Eeuo pipefail

CONTAINER="decipher-api-1"

usage() {
  cat <<'EOF'
Usage:
  ./decipher_config_check.sh [--container NAME]

Options:
  --container NAME  DECIPHER API container (default: decipher-api-1)
  -h, --help        Show this help

Exit code: 0 when all checks pass, 1 otherwise.
EOF
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --container) CONTAINER="${2:?missing value for $1}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage ;;
  esac
done

if [[ "$(docker inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" != "true" ]]; then
  echo "ERROR: container ${CONTAINER} is not running (see: docker ps)" >&2
  exit 1
fi

docker exec -i "$CONTAINER" python - <<'PY'
import json
import ssl
import sys
import urllib.request

from pyflowintel import (
    FlowintelAuthenticationError,
    FlowintelConnectionError,
    FlowintelUnauthorizedError,
    PyFlowintel,
)

from decipher import settings
from decipher.settings import DECIPHER_CONFIG_PATH
from decipher.runtime_settings import load_decipher_runtime_cfg

API_URL = "http://127.0.0.1:8000"
failures = 0


def report(passed, message):
    global failures
    print(("[OK]   " if passed else "[FAIL] ") + message)
    failures += not passed


def request(url, headers=None, data=None, verify_ssl=True):
    """Send a GET request, or a POST request when data is given; return the JSON body."""
    context = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()
    req = urllib.request.Request(url, data=data, headers=headers or {})
    with urllib.request.urlopen(req, timeout=10, context=context) as response:
        body = response.read()
    return json.loads(body) if body.strip().startswith((b"{", b"[")) else None


print("== DECIPHER API")
try:
    health = request(f"{API_URL}/health")
    report(True, f"GET /health: {json.dumps(health)}")
    for alert_type in ("suspicious_login", "suspicious_nt_scanning"):
        report(alert_type in health.get("available_types", []), f"Analyzer registered: {alert_type}")
except Exception as error:
    report(False, f"GET /health failed: {error}")

print("\n== Configuration (values loaded by the API)")
misp_url, misp_key = settings.MISP_URL, settings.MISP_API_KEY
flowintel_cfg = settings.settings_data.get("flowintel") or {}
flowintel_url, flowintel_key = flowintel_cfg.get("base_url", ""), flowintel_cfg.get("api_key", "")
runtime = load_decipher_runtime_cfg()
report(bool(misp_url), f"decipher-settings.yaml misp.url: {misp_url or 'empty'}")
report(bool(misp_key), "decipher-settings.yaml misp.api_key: " + ("set" if misp_key else "empty"))
report(bool(flowintel_url), f"decipher-settings.yaml flowintel.base_url: {flowintel_url or 'empty'}")
report(bool(flowintel_key), "decipher-settings.yaml flowintel.api_key: " + ("set" if flowintel_key else "empty"))
report(runtime.enable_misp_search, f"decipher-runtime-cfg.yaml enable_misp_search: {runtime.enable_misp_search}")
report(not runtime.enable_case_creation,
       f"decipher-runtime-cfg.yaml enable_case_creation: {runtime.enable_case_creation} (RADAR creates the cases)")
print("       Note: the API reads decipher-settings.yaml at startup; restart the API when editing this file.")

print(f"\n== MISP ({misp_url})")
if misp_url and misp_key:
    misp_headers = {"Authorization": misp_key, "Accept": "application/json"}

    def misp_get(path):
        return request(misp_url.rstrip("/") + path, misp_headers, verify_ssl=settings.MISP_VERIFY_SSL)

    try:
        report(True, f"Reachable and valid API key (version {misp_get('/servers/getVersion').get('version')})")
    except Exception as error:
        report(False, f"Request failed: {error}")
else:
    report(False, "Skipped: misp.url or misp.api_key is empty")

print(f"\n== Flowintel ({flowintel_url})")
if flowintel_url and flowintel_key:
    # Flowintel has no health endpoint, so we request one case with PyFlowintel. A missing case is a valid answer; only the API key is checked.
    # No "with" block: PyFlowintel.__exit__ suppresses exceptions, which would hide a rejected key.
    try:
        client = PyFlowintel.from_config(str(DECIPHER_CONFIG_PATH))
        try:
            client.cases.search_by_id(1)
        finally:
            client.close()
        report(True, "Reachable and valid API key")
    except (FlowintelAuthenticationError, FlowintelUnauthorizedError) as error:
        report(False, f"Reachable, but the API key is rejected: {error}")
    except FlowintelConnectionError as error:
        report(False, f"Not reachable: {e./drror}")
    except Exception as error:
        report(False, f"Request failed: {error}")
else:
    report(False, "Skipped: flowintel.base_url or flowintel.api_key is empty")

print(f"\nSummary: {failures} failed")
print("RADAR side: check Connectors > DECIPHER > Test connection in the RADAR GUI.")
sys.exit(1 if failures else 0)
PY
