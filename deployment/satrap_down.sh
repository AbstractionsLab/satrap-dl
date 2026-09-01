#!/usr/bin/env bash
set -Eeuo pipefail

# Stops the SATRAP deployment stack

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.satrap.yml"
PROJECT="satrap"

usage() {
  cat <<'EOF'
Usage:
  ./satrap_down.sh [--purge]

Options:
  --purge: also remove the typedb-data named volume (destroys the knowledge base) and the satrap image
  -h, --help: show this help
EOF
  exit 2
}

clean_all=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge) clean_all=true; shift ;;
    -h|--help) usage ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage
      ;;
  esac
done

if [[ ! -f "$COMPOSE_FILE" ]]; then
  echo "ERROR: compose file not found: $COMPOSE_FILE" >&2
  exit 1
fi

SATRAP_VERSION=$(awk -F ' *= *' \
  '/^version/ {gsub(/["'\'']/,"",$2); print $2; exit}' \
  "${SCRIPT_DIR}/../pyproject.toml")

# temporary file to pass the shell env var to the docker compose environment
COMPOSE_ENV_FILE="$(mktemp -t satrap-compose-env.XXXXXX)"
trap 'rm -f "$COMPOSE_ENV_FILE"' EXIT
cat >"$COMPOSE_ENV_FILE" <<EOF
SATRAP_VERSION=${SATRAP_VERSION}
EOF

compose_args=(-p "$PROJECT" -f "$COMPOSE_FILE" --env-file "$COMPOSE_ENV_FILE")

if [[ "$clean_all" == "true" ]]; then
  echo "Stopping the SATRAP stack, removing volumes and satrap image..."
  docker compose "${compose_args[@]}" down -v --rmi local
else
  echo "Stopping the SATRAP stack..."
  docker compose "${compose_args[@]}" down
fi
