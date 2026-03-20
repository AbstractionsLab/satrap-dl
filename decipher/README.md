# DECIPHER

_Detection, Enrichment, Correlation, Incident, Playbook, Handling, Escalation and Recovery_ (**DECIPHER**) is a subsystem of SATRAP-DL responsible of supporting automated workflows for handling diverse types of incidents, informed by CTI and relying on open-source tools.

DECIPHER provides a REST-based service for analyzing security alerts from predefined threat scenarios and creating prioritized cases based on a computed severity score.

## Table of contents

- [Overview](#overview)
- [Features](#features)
- [Getting started](#getting-started)
- [Usage](#usage)
- [Unit tests](#unit-tests)
- [Project status](#project-status)
- [Roadmap](#roadmap)

## Overview

CyFORT supports the implementation of an automated incident **(H)andling** pipeline enabled by the [Active Response module of RADAR](https://github.com/AbstractionsLab/idps-escape/blob/main/docs/manual/radar_docs/radar-active-response.md), a subsystem of [IDPS-ESCAPE](https://github.com/AbstractionsLab/idps-escape), and the DECIPHER REST analysis service hosted in this repository. Roughly, the workflow steps include:

1. **(D)etect** and create alerts in [Wazuh](https://wazuh.com/) for the selected threat scenario.
2. **(E)nrich** by searching for CTI related to the alert IOCs in [MISP](https://www.misp-project.org/).
3. **(C)orrelate** and determine a CTI severity score via an automated preliminary analysis on the enriched alerts.
4. Compute a [RADAR risk score](https://github.com/AbstractionsLab/idps-escape/blob/main/docs/manual/radar_docs/radar-risk-math.md) on the alert based on detection and CTI factors, and assign a triage tier.
5. **(E)scalate (I)ncidents** to prioritized cases in [Flowintel](https://flowintel.github.io/flowintel-doc/#/).
6. Add relevant **(P)laybooks** to the case for further interactive analysis, e.g., [SATRAP playbooks](https://github.com/AbstractionsLab/satrap-dl/blob/main/docs/manual/playbooks.md) or [MISP playbooks](https://github.com/MISP/misp-playbooks).

**(R)ecovery** actions are left to the judgment of incident responders. Yet, the CTI analysis and playbook outcomes can inform recovery decisions.

This folder hosts the implementation of the DECIPHER analysis REST service, which deals with steps 2, 3, 5 and 6 of the described workflow.

## Features

- **Extensible REST API**: Analysis endpoints, extensible for handling diverse threat scenarios
- **MISP enrichment**: Real-time IOC search and threat intelligence retrieval from MISP via PyMISP
- **Threat scoring**: Configurable severity score calculation based on severity and confidence factors such as an event threat level, admiralty scale, sightings, and MITRE ATT&CK tags.
- **Case management**: Automated case creation in Flowintel via PyFlowintel, with an analysis report and priority tags 
- **Auto-reloadable config**: No restart required for analysis or scoring parameter changes
- **Containerized deployment**: Single-command deployment using the [deployment scripts](../deployment/) of SATRAP-DL's infrastructure stack.

## Getting started

Here, we describe how to configure and run the REST service. For deployment of the whole DECIPHER infrastructure stack, see the [deployment README](/deployment/README.md). 

### Prerequisites

* [Docker engine](https://docs.docker.com/engine/) running

### Configuration

DECIPHER uses three YAML configuration files located in the `/config/` folder at the project root:

- **`decipher-settings.yaml`** — Service settings (logging, MISP, Flowintel). Requires service restart to take effect.
- **`decipher-runtime-cfg.yaml`** — Runtime options, e.g., whether MISP and/or Flowintel shall be used in the analysis. No restart needed.
- **`decipher-scoring-cfg.yaml`** — Threat scoring weights. Changes take effect without restart.

Copy each template file in the [config templates folder](../config/) into a file where `.template` is removed from the name (e.g., `decipher-settings.template.yaml` $\rightarrow$ `decipher-settings.yaml`) and update the copied files with your settings.

See the corresponding templates for detailed parameter descriptions.

### Setup

1. Clone or download this repository.

    ```sh
    git clone https://github.com/AbstractionsLab/satrap-dl.git
    ```

2. From the root of the project, build and start the service:

    ```bash
    cd deployment
    ./decipher_up.sh --api
    ```

### Stop the service

```bash
./decipher_down.sh --api
```

### View the service logs

```bash
docker logs decipher-api-<x> -f
```

replacing `<x>` with the suffix of your running container.

## Usage

### REST API endpoints

Check the service health:

```bash
curl http://localhost:8000/health
```

List available analyzers:

```bash
curl http://localhost:8000/api/v0.1/analyzers
```

Analyze a suspicious login alert:

```bash
curl -X POST http://localhost:8000/api/v0.1/analyze/suspicious_login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "target_host": "10.0.0.1",
    "src_ips": ["185.220.100.1"],
    "timestamp": "2026-01-31T10:00:00Z"
  }'
```

Create an incident case (typically after performing analysis).

```bash
curl -X POST http://localhost:8000/api/v0.1/incident \
  -H "Content-Type: application/json" \
  -d '{
    "priority_level": "high",
    "title": "Multiple login attempts from external IP",
    "description": {
      "system_affected": "My database server",
      "detected_by": "SIEM"
    }
  }'
```

See the API documentation at `http://localhost:8000/docs` for more details.

### Examples
Find sample scripts for testing the analysis and incident creation endpoints in the `tests/decipher/integration` folder. A script for ingesting test data in MISP is included too.


## Unit tests

From the project root, run all DECIPHER tests with (requires poetry or the VS Code development environment):

```bash
poetry install --only main,decipher
poetry run ./run_tests.sh decipher
```


## Project status
Currently, DECIPHER provides minimal functionality to enable a fully automated incident handling pipeline. Future iterations consider the extensions and refinements described in the Roadmap.

⚠️ **Alpha Software Disclaimer**: DECIPHER is a SATRAP-DL component under active development. May include incomplete features and bugs. Not intended for production use.

## Roadmap

- Add analyzers for new threat scenarios (next: ransomware, increased log volume)
- Refine the CTI scoring formula based on other available tags, object grouping and [MISP decaying models](https://github.com/MISP/misp-decaying-models)
- Integrate SATRAP in the CTI analysis phase to leverage logic-based reasoning capabilities
- Support the use of templates for diverse threat scenarios when creating cases (related to [PyFlowintel](https://github.com/AbstractionsLab/PyFlowintel) and [Flowintel features](https://github.com/flowintel/flowintel-roadmap/issues/15))
- Create playbooks for post-incident analysis integrated with SATRAP
- Add external playbook recommendations based on threat scenarios
