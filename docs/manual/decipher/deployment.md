# DECIPHER infrastructure stack

The infrastructure stack on which [DECIPHER](../decipher/README.md) operates consists of:

- **Wazuh** as the SIEM of an organization
- **MISP** as the CTI platform hosting a CTI repository
- **Flowintel** as a case management system.
- **DECIPHER analysis service** as the provider of an automated CTI-informed incident handling pipeline

The deployment artifacts for this stack are hosted in the [deployment folder](/deployment/) of the SATRAP-DL project. The deployment follows a containerized architecture model and relies on a single entrypoint script and a single configuration file.
> **Note:** For deploying Wazuh with RADAR (Risk-aware Anomaly Detection-based Automated Response), please refer to the corresponding instructions in the [IDPS-ESCAPE repository](https://github.com/AbstractionsLab/idps-escape).


## Configuration setup

The `env-template` file contains all the configuration variables for both, MISP and Flowintel, taken as such from the official [MISP template.env](https://github.com/MISP/misp-docker/blob/master/template.env) and [FlowIntel template.env](https://github.com/flowintel/flowintel/blob/main/template.env) files.

Typical values configured here include MISP admin settings and base URL, service ports (MISP HTTP/HTTPS, FlowIntel app port) and database credentials.

1. Copy the template to a `.env` file: 
```bash
cp env-template .env
```
2. Set the values in `.env` according to your environment.



### Key Environment Variables

**MISP Core:**
- `MISP_BASE_URL` - The URL where MISP will be accessible (default: `https://localhost`)
- `MISP_ADMIN_EMAIL` - Admin user email (default: `admin@admin.test`)
- `MISP_ADMIN_ORG` - Organization name (default: `ORGNAME`)

**FlowIntel:**
- `FLOWINTEL_VERSION` - Version of FlowIntel to deploy (default: `3.1.0`, pinned in `env-template`)
- `FLOWINTEL_APP_PORT` - Application port (default: `7006`)

**DECIPHER API:**
- `API_VERSION` - Tag of the locally built DECIPHER API image, i.e. `decipher/api:$API_VERSION` (default: `latest`)
- `API_PORT` - Port on which the REST API is published (default: `8000`)

For comprehensive documentation on all available environment variables, please refer to the official sources. E.g., [MISP Docker official documentation](https://github.com/MISP/misp-docker#readme).


## Bringing up the stack

The `decipher_up.sh` script provides a single entrypoint to bring up all the available services:

1. Ensure execution permissions:
```bash
chmod +x decipher_up.sh
```

2. Run:

```bash
./decipher_up.sh [--misp | --flowintel | --api | --all]
```

**Available options:**
- `--misp`: brings up MISP stack (CTI platform)
- `--flowintel`: brings up FlowIntel stack (case management system)
- `--api`: brings up DECIPHER REST API service
- `--all`: brings up all stacks (MISP, FlowIntel, and DECIPHER API)

**Usage examples:**
```bash
./decipher_up.sh --misp                      # MISP only
./decipher_up.sh --api                       # DECIPHER API only
./decipher_up.sh --misp --flowintel          # MISP and FlowIntel together
./decipher_up.sh --all                       # All stacks
```

The script uses adapted versions of the official docker-compose files from [MISP](https://github.com/MISP/misp-docker/blob/master/docker-compose.yml) and [FlowIntel](https://github.com/flowintel/flowintel/blob/main/docker-compose.yml), modified for shared configuration (`env-template`) and network/naming adjustments.

**Exposed ports:** (configure in `.env`)
- MISP: HTTP/HTTPS (i.e., 80/443)
- FlowIntel: Application port (default 7006)
- DECIPHER API: REST API port (default 8000, set `API_PORT` to change it)

## Stopping the services

The script `decipher_down.sh` stops (brings down) the DECIPHER infrastructure stack or selected applications.

1. Ensure execution permissions:
```bash
chmod +x decipher_down.sh
```

2. Run:
```bash
./decipher_down.sh [--misp | --flowintel | --api | --all] [--purge]
```

**Available options:**
- `--misp`: brings down the MISP stack
- `--flowintel`: brings down the FlowIntel stack
- `--api`: brings down the DECIPHER REST API
- `--all`: brings down all stacks
- `--purge`: removes all named volumes for the selected stacks, useful for complete cleanup or resetting data.

**Usage examples:**
```bash
./decipher_down.sh --api                     # Stop DECIPHER API only
./decipher_down.sh --misp --purge            # Stop MISP and remove volumes
./decipher_down.sh --all --purge             # Stop all stacks and remove volumes
```

## Security of the DECIPHER API container

The DECIPHER API image and service implement the following security measures:

- The image is built in two stages, so the build tooling never reaches the runtime image.
- The service runs as the non-root system user `decipher`. The application code and its virtual environment are owned by `root`, so the running service can read and execute them but cannot modify them.
- The host's `config/` folder is mounted read-only. Edits made on the host take effect without restarting the container because the runtime and scoring configurations are reloaded whenever these files change.

Two aspects to be aware of:

- Enabling `logging.enable_file_logging` in `config/decipher-settings.yaml` requires adding a writable bind mount for the log directory in the host. By default the API logs to standard output, readable with `docker logs`.
- Currently, the API exposes no authentication and its interactive documentation is enabled, so the published port should not be reachable from untrusted networks. Restrict it to the host with `API_PORT` bound to a loopback address, or place the service behind an authenticating reverse proxy.

<br/>

[Back to home](/docs/manual/decipher/README.md)
