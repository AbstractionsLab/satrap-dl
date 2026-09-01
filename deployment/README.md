# SATRAP-DL deployment artifacts

This folder contains the Docker Compose files and deployment entrypoint scripts for both, SATRAP and DECIPHER. Detailed setup and usage instructions are available in the respective deployment manuals linked below.

## SATRAP

Artifacts to run TypeDB and the SATRAP CLI image:

- [satrap_up.sh](satrap_up.sh) — bring up TypeDB and build the SATRAP image
- [satrap_down.sh](satrap_down.sh) — stop the SATRAP stack (`--purge` also removes the volume and image)
- [docker-compose.satrap.yml](docker-compose.satrap.yml) — `typedb` and build-only `satrap` services, the `typedb-data` volume, and the `satrap-net` network

See the [SATRAP deployment reference](../docs/manual/satrap/deployment_artifacts.md) for setup and usage.

## DECIPHER

Artifacts to run the DECIPHER infrastructure stack (MISP, FlowIntel, and the DECIPHER API):

- [decipher_up.sh](decipher_up.sh) / [decipher_down.sh](decipher_down.sh) — single entrypoint to bring the stack up or down (`--misp | --flowintel | --api | --all`)
- [docker-compose.misp.yml](docker-compose.misp.yml) — MISP (CTI platform)
- [docker-compose.flowintel.yml](docker-compose.flowintel.yml) — FlowIntel (case management)
- [docker-compose.decipher.yml](docker-compose.decipher.yml) — DECIPHER REST API service
- [flowintel-templates/](flowintel-templates/) — FlowIntel template assets
- [env-template](env-template) — shared configuration template for the MISP and FlowIntel stacks; copy it to `.env` and adjust for your environment

See the [DECIPHER infrastructure stack](../docs/manual/decipher/deployment.md) manual for setup and usage.
