#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./decipher_up.sh [--misp | --flowintel | --api | --all]

Options:
  --misp: bring MISP up
  --flowintel: bring FlowIntel up
  --api: bring the DECIPHER REST API up
  --all: bring all stacks up

Examples:
  ./decipher_up.sh --misp
  ./decipher_up.sh --flowintel --api
EOF
  exit 2
}

misp_up=false
flowintel_up=false
api_up=false
all_up=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --misp) misp_up=true; shift ;;
    --flowintel) flowintel_up=true; shift ;;
    --api) api_up=true; shift ;;
    --all) all_up=true; shift ;;
    -h|--help) usage ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage
      ;;
  esac
done

if [[ "$misp_up" == "false" && "$flowintel_up" == "false" && "$api_up" == "false" && "$all_up" == "false" ]]; then
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

if [[ "$api_up" == "true" ]]; then
  up_stack "docker-compose.decipher.yml" "decipher"
fi

if [[ "$all_up" == "true" ]]; then
  misp_up=true
  flowintel_up=true
  api_up=true
  up_stack "docker-compose.misp.yml" "misp"
  up_stack "docker-compose.flowintel.yml" "flowintel"
  up_stack "docker-compose.decipher.yml" "decipher"
fi

