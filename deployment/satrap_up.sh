#!/usr/bin/env bash
set -euo pipefail

# Brings up the SATRAP deployment stack: a TypeDB server and the satrap image

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.satrap.yml"
PROJECT="satrap"

usage() {
  cat <<'EOF'
Usage:
  ./satrap_up.sh [--typedb | --satrap] [-p PORT]

Options:
  --typedb: bring up the TypeDB server (detached, persistent)
  --satrap: build (force) the satrap image
  -p, --port PORT: host port on which to publish the TypeDB server (default: 1729)
  -h, --help: show this help

Default (no flags): bring up TypeDB and build the satrap image
only if it does not already exist.
EOF
  exit 2
}

typedb_up=false
satrap_up=false
satrap_build_if_missing=false
typedb_host_port=1729

while [[ $# -gt 0 ]]; do
  case "$1" in
    --typedb) typedb_up=true; shift ;;
    --satrap) satrap_up=true; shift ;;
    -p|--port)
      if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ ]]; then
        echo "ERROR: $1 requires a numeric PORT value" >&2
        usage
      fi
      typedb_host_port="$2"; shift 2 ;;
    -h|--help) usage ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage
      ;;
  esac
done

# With no flags, bring up TypeDB and build the satrap image only if it is missing.
if [[ "$typedb_up" == "false" && "$satrap_up" == "false" ]]; then
  typedb_up=true
  satrap_build_if_missing=true
fi

# A port only applies when TypeDB is brought up.
if [[ "$typedb_up" == "false" && "$typedb_host_port" != "1729" ]]; then
  echo "TypeDB was not selected; ignoring the port."
fi

if [[ ! -f "$COMPOSE_FILE" ]]; then
  echo "ERROR: compose file not found: $COMPOSE_FILE" >&2
  exit 1
fi

# Derive the version for the image tag (satrap:<version>) from pyproject.toml
# -F sets a field separator in the toml file; then
# find the line starting with 'version' and replace single and/or double quotes
# in the 2nd token ($2) with an empty string.
SATRAP_VERSION=$(awk -F ' *= *' \
  '/^version/ {gsub(/["'\'']/,"",$2); print $2; exit}' \
  "${SCRIPT_DIR}/../pyproject.toml")

# Create a temporary file with the env variables to pass them to Compose. 
# Added to support `sudo docker` which wraps the command call in a new environment;
# a file given as an argument carries the context to the docker compose environment
COMPOSE_ENV_FILE="$(mktemp -t satrap-compose-env.XXXXXX)"
trap 'rm -f "$COMPOSE_ENV_FILE"' EXIT
cat >"$COMPOSE_ENV_FILE" <<EOF
SATRAP_VERSION=${SATRAP_VERSION}
TYPEDB_HOST_PORT=${typedb_host_port}
EOF

compose_args=(-p "$PROJECT" -f "$COMPOSE_FILE" --env-file "$COMPOSE_ENV_FILE")

if [[ "$typedb_up" == "true" ]]; then
  echo "Starting TypeDB (satrap:${SATRAP_VERSION} stack) on host port ${typedb_host_port}..."
  docker compose "${compose_args[@]}" up -d typedb
fi

satrap_image_exists() {
  docker image inspect "satrap:${SATRAP_VERSION}" >/dev/null 2>&1
}

if [[ "$satrap_up" == "true" ]]; then
  echo "Building satrap:${SATRAP_VERSION} image..."
  docker compose "${compose_args[@]}" build satrap
elif [[ "$satrap_build_if_missing" == "true" ]]; then
  if satrap_image_exists; then
    echo "Image satrap:${SATRAP_VERSION} already exists; skipping build. Run './satrap_up.sh --satrap' to rebuild."
  else
    echo "Building satrap:${SATRAP_VERSION} image ..."
    docker compose "${compose_args[@]}" build satrap
  fi
fi

echo "Done. Run SATRAP from the SATRAP-DL root with: ./satrap.sh <command>"
