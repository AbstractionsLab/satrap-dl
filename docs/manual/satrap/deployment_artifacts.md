# SATRAP deployment reference

To be operational, SATRAP requires:

- **TypeDB** as the long-running server hosting the CTI knowledge base
- **A SATRAP image** either as a standalone command-line interface or for development in VS Code

The deployment follows a containerized architecture model defined in [docker-compose.satrap.yml](/deployment/docker-compose.satrap.yml), which declares the persistent `typedb-data` volume, the long-running `typedb` service, and a build-only `satrap` service (the CLI image), sharing the `satrap-net` Docker network. 

Two entrypoint scripts allow for simple deployment and removal of the stack components.

> **Note:** The scripts use paths relative to their own location, so they can be invoked from any working directory. The examples below assume the project root folder.

## Bringing up the stack

The [satrap_up.sh](/deployment/satrap_up.sh) script provides a single entrypoint to bring up TypeDB and build the SATRAP image.

1. Ensure execution permissions:

    ```bash
    chmod +x deployment/satrap_up.sh
    ```

2. Run:

    ```bash
    ./deployment/satrap_up.sh [--typedb | --satrap] [-p PORT]
    ```

**Available options:**

- `--typedb`: bring up the TypeDB server only (detached and persistent); useful for the development container, where the CLI image is not needed or restarting if TypeDB has been stopped
- `--satrap`: build (force) the SATRAP image only; useful for updates to the code or upgrading version
- `-p, --port PORT`: host port on which to publish the TypeDB server (default: `1729`)

With no flags, the script brings up TypeDB and builds the SATRAP image only if it does not already exist. To force a rebuild, use the `--satrap` option.

**Usage examples:**

```bash
./deployment/satrap_up.sh                    # TypeDB + build image if missing
./deployment/satrap_up.sh --typedb           # TypeDB only
./deployment/satrap_up.sh --satrap           # Force-rebuild the SATRAP image only
./deployment/satrap_up.sh -p 1730            # Publish TypeDB on host port 1730
```

**Exposed ports:**

- TypeDB: `1729` (default), reachable from the host, e.g. to connect from [TypeDB Studio](https://github.com/typedb/typedb-studio/releases/tag/2.28.6)

## Running SATRAP commands

Once the stack is up, the [satrap.sh](/satrap.sh) script runs a single SATRAP command as a one-shot container connected to `satrap-net`. It runs as the invoking host user, with the configuration file, logs, and STIX data bind-mounted from `satrap/assets/`.

```bash
./satrap.sh              # Show the help menu
./satrap.sh setup        # Create the knowledge base
./satrap.sh etl          # Ingest STIX data
```

See the [SATRAP CLI interface section](./interfaces.md#satrap-cli-for-cti-skb-management) for the full command reference.

## Stopping the stack

The [satrap_down.sh](/deployment/satrap_down.sh) script stops (brings down) the SATRAP stack.

1. Ensure execution permissions:

    ```bash
    chmod +x deployment/satrap_down.sh
    ```

2. Run:

    ```bash
    ./deployment/satrap_down.sh [--purge]
    ```

**Available options:**

- `--purge`: also remove the `typedb-data` volume (destroys the knowledge base) and the SATRAP image, for a complete cleanup or a data reset

**Usage examples:**

```bash
./deployment/satrap_down.sh                  # Stop the stack, keep the knowledge base
./deployment/satrap_down.sh --purge          # Stop and remove the volume and image
```

<br/>

[Back to home](/docs/manual/satrap/README.md)