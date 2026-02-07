#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./decipher_up.sh [--misp] [--flowintel]

Behavior:
  - If --misp is provided: docker compose up -d using docker-compose.misp.yml
  - If --flowintel is provided: docker compose up -d using docker-compose.flowintel.yml
  - If both are provided: both stacks are brought up

Examples:
  ./decipher_up.sh --misp
  ./decipher_up.sh --flowintel
  ./decipher_up.sh --misp --flowintel
EOF
  exit 2
}

misp_up=false
flowintel_up=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --misp) misp_up=true; shift ;;
    --flowintel) flowintel_up=true; shift ;;
    -h|--help) usage ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage
      ;;
  esac
done

if [[ "$misp_up" == "false" && "$flowintel_up" == "false" ]]; then
  echo "Nothing to deploy. See options below."
  usage
  exit 0
fi

up_stack() {
  local file="$1"
  local project="$2"

  if [[ ! -f "$file" ]]; then
    echo "ERROR: compose file not found: $file" >&2
    exit 1
  fi

  docker compose -p "$project" -f "$file" up -d
}

if [[ "$misp_up" == "true" ]]; then
  up_stack "docker-compose.misp.yml" "misp"
fi

if [[ "$flowintel_up" == "true" ]]; then
  up_stack "docker-compose.flowintel.yml" "flowintel"
fi

