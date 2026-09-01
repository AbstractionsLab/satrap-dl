# Installation

DECIPHER is a containerized service designed to be deployed as part of the SATRAP-DL infrastructure stack. Two deployment options are available:

- A [standalone REST API service](#standalone-rest-api-service)
- A [full infrastructure stack](#full-infrastructure-stack) including MISP and Flowintel

## Prerequisites

- [Docker engine](https://docs.docker.com/engine/) running
- [Docker Compose](https://docs.docker.com/compose/) installed

To get started, clone or download the SATRAP-DL repository:

```sh
git clone https://github.com/AbstractionsLab/satrap-dl.git
cd satrap-dl
```

## Standalone REST API service

If you already have MISP and Flowintel instances running, simply run the DECIPHER API service.

### Steps

1. In a terminal, go to the project root folder and ensure execution rights on scripts:

    ```sh
    chmod +x deployment/*.sh
    ```

2. Create copies of the configuration template files in the `config/` folder, removing `.template` from the filenames:

    ```sh
    cp config/decipher-settings.template.yaml config/decipher-settings.yaml
    cp config/decipher-runtime-cfg.template.yaml config/decipher-runtime-cfg.yaml
    cp config/decipher-scoring-cfg.template.yaml config/decipher-scoring-cfg.yaml
    ```

3. Customize the copied configuration files with your settings. See [Configuration](/docs/manual/decipher/configuration.md) for details.

4. Build and start the DECIPHER API service:

    ```sh
    cd deployment
    ./decipher_up.sh --api
    ```

5. Verify the service is running:

    ```bash
    curl http://localhost:8000/health
    ```

    The published port is `API_PORT` from the `.env` file of the deployment folder, `8000` by default. See the [deployment reference](./deployment.md) for the environment variables of the stack.

The `config/` folder of the host is mounted read-only in the container, so the runtime and scoring configurations can be edited on the host and take effect on the next analysis. Changes to `decipher-settings.yaml` still require restarting the container.

### Next steps

Before running an analysis, complete the [MISP instance setup](/docs/manual/decipher/configuration.md#misp-instance-setup) on the MISP instance configured in `config/decipher-settings.yaml`.

### Stopping the service

```bash
cd deployment
./decipher_down.sh --api
```

### Viewing service logs

```bash
docker logs decipher-api-<x> -f
```

Replace `<x>` with the suffix of your running container.

## Full infrastructure stack

For a complete deployment of the DECIPHER infrastructure stack, including MISP and Flowintel.

### Steps

1. Go to the project root folder and ensure execution rights on scripts:

    ```sh
    chmod +x deployment/*.sh
    ```

2. Create copies of all configuration templates in the `config/` folder, and update the MISP and Flowintel settings as required.

3. Bring up the full infrastructure stack:

    ```sh
    cd deployment
    ./decipher_up.sh --all
    ```

4. This will start:
   - DECIPHER API service (default port 8000)
   - MISP instance (default port 80, 443)
   - Flowintel instance (default port 7006)

5. Verify services are running:

    ```bash
    docker ps | grep decipher
    ```

6. Set up the MISP instance: enable the taxonomies and the warninglists used by the analyzers, as described in [MISP instance setup](/docs/manual/decipher/configuration.md#misp-instance-setup).

### Stopping the full stack

```bash
cd deployment
./decipher_down.sh --all
```

## Docker Compose options

The deployment scripts rely on the following Docker Compose files:

- `docker-compose.decipher.yml` — DECIPHER API service only
- `docker-compose.misp.yml` — MISP integration
- `docker-compose.flowintel.yml` — Flowintel integration

Each configuration can be used independently for custom deployments. See the [deployment reference](./deployment.md) for more details.



[Back to home](/docs/manual/decipher/README.md)
