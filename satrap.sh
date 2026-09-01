#!/bin/bash
#
# Runner for the `satrap` image (see Dockerfile.satrap).

# Absolute path of this script, used below to ensure the commands run
# regardless of the path where the script is called from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Refuse to run as root: id -u would be 0 and `--user 0:0` below would run the
# container as root, defeating the image's non-root design.
if [ "$(id -u)" -eq 0 ]; then
    echo "Error: attempt at running satrap.sh as root; run it instead as a regular user." >&2
    exit 1
fi

# Application folder matching PROJECT_HOME inside the Dockerfile.satrap image
PROJECT_HOME="/satrap-dl"
CONTAINER_NAME="${CONTAINER_NAME:-satrap-cli}"
NETWORK="satrap-net"

# Derive the image tag (satrap:<version>) from the version in pyproject.toml
IMAGE_NAME=$(awk -F ' *= *' \
            '/^version/ {gsub(/["'\'']/,"",$2); print "satrap:" $2; exit}' \
            "${SCRIPT_DIR}/pyproject.toml")

# Host configuration file (read-only) and host directories written at runtime
# (writable, persistent): logs and downloaded STIX data.
PARAMS_FILE="${SCRIPT_DIR}/satrap/assets/satrap_params.yml"
LOGS_DIR="${SCRIPT_DIR}/satrap/assets/logs"
STIXDATA_DIR="${SCRIPT_DIR}/satrap/assets/stixdata"

if ! docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
    echo "Error: image ${IMAGE_NAME} not found. Build it first with ./deployment/satrap_up.sh" >&2
    exit 1
fi

if ! docker network inspect "${NETWORK}" >/dev/null 2>&1; then
    echo "Error: Docker network '${NETWORK}' not found. Run ./deployment/satrap_up.sh first." >&2
    exit 1
fi

# Ensure the host directories for the bind mounts exist
mkdir -p "${LOGS_DIR}" "${STIXDATA_DIR}"

# Run the container as the host user to grant write access to the bind-mounted
# folders. With no arguments, the image's default CMD (-h) applies.
docker run -it --rm --name "${CONTAINER_NAME}" \
    --user "$(id -u):$(id -g)" \
    --network "${NETWORK}" \
    -v "${PARAMS_FILE}:${PROJECT_HOME}/satrap/assets/satrap_params.yml:ro" \
    -v "${LOGS_DIR}:${PROJECT_HOME}/satrap/assets/logs" \
    -v "${STIXDATA_DIR}:${PROJECT_HOME}/satrap/assets/stixdata" \
    "${IMAGE_NAME}" "$@"
