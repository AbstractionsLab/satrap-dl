# SATRAP-DL

<img src="./docs/manual/_figures/CyFORT-SATRAP-AlphaLogo.png" alt="cyfort_logo" width="430" align="right" />

## Table of contents

- [Overview](#overview)
- [SATRAP-DL suite](#satrap-dl-suite)
- [Getting started](#getting-started)
- [Documentation and technical specifications](#documentation-and-technical-specifications)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Contact](#contact)

## Overview

SATRAP-DL, short for **Semi-Automated Threat Reconnaissance and Analysis Powered by DECIPHER Logic**, offers a suite of tools for computer-aided CTI analysis and automated incident handling informed by CTI, provided respectively by its sub-systems _SATRAP_ and _DECIPHER_.

This repository contains the source code and documentation of SATRAP-DL, including the [technical specifications](https://abstractionslab.github.io/satrap-dl/docs/traceability/index.html). SATRAP-DL has been developed in alignment with the [C5-DEC](https://github.com/AbstractionsLab/c5dec) method. Among others, C5-DEC prescribes and supports (with the C5-DEC CAD software) the storage, interlinking and processing of all software development life cycle (SDLC) artifacts in a unified manner.

## SATRAP-DL suite

- [**SATRAP**](satrap/README.md) provides a platform for (semi-)automated analysis of CTI based on a knowledge representation system for explainable inference. It aims to reduce the manual effort involved in correlating threat intelligence and deriving actionable conclusions, while keeping the analysis over STIX 2.1 CTI data traceable.

- [**DECIPHER**](decipher/README.md) provides an extensible REST service for real-time analysis of alert information and incident case creation for streamlined investigations of threat scenarios.

- [**PyFlowintel**](https://github.com/AbstractionsLab/PyFlowintel) is a Python library for interacting with the case management platform [Flowintel](https://github.com/flowintel/flowintel) through its REST API. PyFlowintel is used to support automated pipelines in DECIPHER.

## Getting started

This repository is organized as follows:

- [satrap/](satrap/): SATRAP Python package (KRS, ETL, CLI, analysis toolbox)
- [decipher/](decipher/): DECIPHER Python package (analysis service REST API)
- [deployment/](deployment/): artifacts to deploy the operational environment of DECIPHER (SATRAP will be included in the future)
- [docs/](docs/): user manual, notebooks, specs, and traceability artifacts
- [tests/](tests/): unit and integration tests
- [tutorials/](tutorials/): workshop and tutorial materials
- [.devcontainer/](.devcontainer/): VS Code configuration for a ready-to-use containerized development environment


For detailed setup and usage instructions of each sub-system, please refer to the corresponding README using the links above.

## Documentation and technical specifications

The technical specifications of SATRAP-DL including requirements, architecture design, and test artifacts, are available on a dedicated [traceability web page](https://abstractionslab.github.io/satrap-dl/docs/traceability/index.html). 

For SATRAP-specific usage guidance, see the [SATRAP user manual](docs/manual/index.md).

## License

Copyright (c) itrust Abstractions Lab and itrust consulting. All rights reserved.

SATRAP-DL is licensed under the [GNU Affero General Public License (AGPL) v3.0](LICENSE) license.

**Note**: SATRAP incorporates a few ideas concerning the inference rules and the analysis functionality from [typedb-cti (2.x)](https://github.com/typedb-osi/typedb-cti/tree/2.x), an open-source project licensed under [Apache License 2.0](./satrap/assets/schema/LICENSE). During the conceptual phase of SATRAP-DL, we considered building SATRAP on top of typedb-cti as they are close in spirit. However, we opted for a fresh development mainly for two reasons:

- the design of typedb-cti was not compatible with the ambitions and architectural requirements of SATRAP
- typedb-cti (2.x) relies on an outdated version of TypeDB 2.x, incompatible with the latest release at the time (2.27).



## Acknowledgments

SATRAP-DL is a sub-project of the [CyFORT](https://abstractionslab.com/index.php/research-and-development/cyfort) project, which in turn stands for "Cloud Cybersecurity Fortress of Open Resources and Tools for Resilience". CyFORT is co-funded by the Ministry of the Economy of Luxembourg, in the context of the EC-approved [IPCEI-CIS](https://ec.europa.eu/commission/presscorner/detail/en/ip_23_6246).


## Contact
For more information about the project, feedback, questions or feature requests, feel free to contact us at Abstractions Lab: info@abstractionslab.lu
