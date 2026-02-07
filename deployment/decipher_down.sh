#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./decipher_down.sh [--misp] [--flowintel] [--purge]

Behavior:
  - If --misp is provided: docker compose down using docker-compose.misp.yml
  - If --flowintel is provided: docker compose down using docker-compose.flowintel.yml
  - If both are provided: both stacks are brought down
  - If --purge is provided: also removes named volumes for the selected stacks

Examples:
  ./decipher_down.sh --misp
  ./decipher_down.sh --flowintel
  ./decipher_down.sh --misp --flowintel
  ./decipher_down.sh --misp --purge
EOF
  exit 2
}

misp_down=false
flowintel_down=false
with_volumes=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --misp) misp_down=true; shift ;;
    --flowintel) flowintel_down=true; shift ;;
    --purge) with_volumes=true; shift ;;
    -h|--help) usage ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage
      ;;
  esac
done

if [[ "$misp_down" == "false" && "$flowintel_down" == "false" ]]; then
  echo "Nothing to stop. See the options below."
  usage
  exit 0
fi

down_stack() {
  local file="$1"
  local project="$2"

  if [[ ! -f "$file" ]]; then
    echo "ERROR: compose file not found: $file" >&2
    exit 1
  fi

  if [[ "$with_volumes" == "true" ]]; then
    docker compose -p "$project" -f "$file" down -v
  else
    docker compose -p "$project" -f "$file" down
  fi
}

if [[ "$misp_down" == "true" ]]; then
  down_stack "docker-compose.misp.yml" "misp"
fi

if [[ "$flowintel_down" == "true" ]]; then
  down_stack "docker-compose.flowintel.yml" "flowintel"
fi
