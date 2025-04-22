# SATRAP-DL

SATRAP-DL, short for _Semi-Automated Threat Reconnaissance and Analysis Powered by Description Logics_, is a sub-project of the [CyFORT](https://abstractionslab.com/index.php/research-and-development/cyfort) project, which in turn stands for "Cloud Cybersecurity Fortress of Open Resources and Tools for Resilience". Project CyFORT is carried out in the context of the EC-approved [IPCEI-CIS](https://ec.europa.eu/commission/presscorner/detail/en/ip_23_6246).

<img src="./docs/manual/_figures/CyFORT-SATRAP-AlphaLogo.png" alt="cyfort_logo" width="500"/>

SATRAP-DL aims at the development of a platform for carrying out interactive computer-aided analysis of cyber threat intelligence (CTI) driven by logic-based automated reasoning and inference. We call this platform **SATRAP**, short for "**Semi-Automated Threat Reconnaissance and Analysis Platform**".

This repository contains the source code and [full documentation](#documentation-and-technical-specifications) of SATRAP. The development of SATRAP relies on the [C5-DEC](https://github.com/AbstractionsLab/c5dec) method and software, also developed as part of project CyFORT, which is, among other things, characterized by storing, interlinking and processing all software development life cycle (SDLC) artifacts in a unified manner; see our end-to-end [traceability web page](https://abstractionslab.github.io/satrap-dl/docs/traceability/index.html) providing the technical specifications of SATRAP.

## Table of contents

- [Overview](#overview)
- [Features](#features)
- [User manual](#user-manual)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Unit and validation tests](#unit-and-validation-tests)
- [Documentation and technical specifications](#documentation-and-technical-specifications)
- [Project status](#project-status)
- [Roadmap](#roadmap)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Contact](#contact)

## Overview

The main purpose of SATRAP is to (semi-)automate deductive processes to simplify the analysis of CTI. In more realistic terms, considering the analysis stage of the CTI lifecycle, we aspire to advance the state-of-the-art by lowering the barrier to the use of automation powered by reasoning engines and inference.

At its core, SATRAP implements a **knowledge representation system (KRS)** consisting of a knowledge base of cyber threat intelligence coupled with a reasoning engine for inferring new knowledge. The KRS grounds SATRAP into formal underpinnings, enabling the introduction of semantics into the storage, processing, and analysis of cyber threat intelligence.

Concretely, users execute certain analytic queries over a CTI knowledge base and SATRAP provides an explainable answer, meaning that the deductive steps that lead to such an answer can be traced. Unlike with regular database queries, the answer might include not only information persisted in the CTI knowledge base, but also non-explicit relations logically derived by an automated reasoning engine from the actual information in the CTI knowledge base.

This automation intends to support memory-intensive analytic tasks, typically concerning correlating CTI and drawing logical conclusions from large amounts of information. This in turn enables to better allocate already scarce resources by allowing analysts to shift their expertise to formulating appropriate questions and translating the results into actionable intelligence.

The set of analytic features offered by SATRAP is foreseen to complement features of existing open-source threat intelligence platforms, such as [MISP](https://misp-project.org/) and [OpenCTI](https://github.com/OpenCTI-Platform/opencti). Integration with such tools for automated inference over CTI streams is expected in future releases, although manual content transfer between SATRAP and such TIPs is already supported by the current release.

## Features

### Functionality

* A toolbox of functions for supporting CTI analysis powered by an inference engine
* An extract-transform-load (ETL) mechanism for ingesting STIX2.1 data from CTI sources into the knowledge base of SATRAP

### Core features
* A knowledge representation system for CTI implemented on top of [TypeDB](https://typedb.com/features) (v2.29.0)
* A data model based on [STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro.html), enabling:
  * exchange of threat information with repositories and security tools such as MITRE ATT&CK data sets, TIPs (e.g., MISP, OpenCTI), SIEM and IDPS (e.g., [IDPS-ESCAPE](https://github.com/AbstractionsLab/idps-escape), Wazuh and Suricata)
  * a common language for reasoning over CTI
* A predefined set of inference rules and queries, extensible with user-defined ones
* An intuitive language for defining new derivation rules in terms of STIX2.1 concepts, thanks to the underlying semantic technology
* A CTI knowledge base that can be directly queried in [TypeQL](https://typedb.com/docs/typeql/2.x/), the native language of TypeDB


### Interfaces
- A command-line interface (SATRAP CLI) for efficient user interaction
- A light-weight Python library (`CTIAnalysisToolbox`) providing a preliminary toolbox of analytic functions for supporting CTI investigations. These functions perform automated reasoning over the information in the knowledge base.
- A frontend based on Jupyter Notebooks importing the CTIAnalysisToolbox for creating playbooks or user-defined queries
- [TypeDB Studio](https://typedb.com/docs/manual/2.x/studio) (third-party, optional), the GUI of TypeDB, for an interactive visualization of explainable queries

 ### Design principles
- Free/libre and open source
- Cross platform: works on GNU/Linux, MacOS and Windows
- Modular design to promote extensibility
- Based on open data formats such as Markdown, YAML, JSON, and HTML
- Secure by design as per the C5-DEC methodology
- Interoperability with well-established open-source TIPs

## User manual

To learn more about the fundamentals of SATRAP as well as details on the installation, setup requirements, usage, and overall functionality, please refer to the [SATRAP user manual](docs/manual/index.md).

## Getting Started

Currently, SATRAP offers two deployment options:

- A command-line interface (CLI) in your OS shell of choice
- A containerized analysis environment in VS Code

Below we describe the deployment of the command-line interface. For the deployment of a development environment, please see the [installation page](docs/manual/installation.md) of the user manual.

### Prerequisites

* [Docker engine](https://docs.docker.com/engine/) running

### Setup

1. Clone or download the source code of this repository.

    ```sh
    git clone https://github.com/AbstractionsLab/satrap-dl.git
    ```

1. In a terminal, go to the project's root folder (when cloning, `satrap-dl`) and ensure execution rights on the scripts.

    ```sh
    cd satrap-dl
    chmod +x *.sh
    ```

1. Run the `init-satrap.sh` script to set up and run a TypeDB server connected to a `satrap-net` Docker network.

    ```sh
    ./init-satrap.sh
    ```

    TypeDB is exposed on port `1729` of the TypeDB Docker container.
1. Run the `build-satrap.sh` script to build a Docker image for SATRAP.

    ```sh
    ./build-satrap.sh
    ```

At this point, the CLI can be used as described in the [Usage](#usage) section below.

If the `typedb` container is stopped for any reason, it can be safely launched again by re-running the `init-satrap.sh` script.

## Usage
### Configuration parameters
The default configuration parameters, including settings for the connection to TypeDB and logging level, can be modified in the file `satrap/assets/satrap_params.yml`. 

Unless otherwise specified, e.g. by command arguments, the CLI and the Python toolbox run the commands and functions using the knowledge base specified by the TypeDB parameters in the mentioned file.

### SATRAP command-line interface
The command-line interface of SATRAP is primarily intended for setting up a fresh CTI knowledge base and executing an extract-transform-load (ETL) pipeline to ingest content in STIX and populate the said knowledge base.

A minimal set of analytical functions is also available through this interface, however, we recommend the use of the Python library described [below](#satrap-as-a-python-library) for tasks related to the analysis of CTI as it provides a larger set of functions.

To access the SATRAP CLI, simply go the project root folder (`cd satrap-dl`) and run:

```sh
./satrap.sh
```

The help menu is shown if no arguments are provided.

<img src="./docs/manual/_figures/satrap-cli.png" alt="satrap_cli" width="80%"/>

#### Quick setup of a CTI SKB with MITRE ATT&CK Enterprise
To create and populate a knowledge base with the [default parameters](#configuration-parameters) run:

```sh
./satrap.sh setup
./satrap.sh etl 
```

This will create a knowledge base called `satrap-skb-alpha` and ingest the latest version of the [MITRE ATT&CK Enterprise](https://github.com/mitre-attack/attack-stix-data) dataset.


For more information about the commands exposed in the CLI, please take a look at the [SATRAP interfaces](docs/manual/interfaces.md) section of the user manual.


### SATRAP as a Python library
We recommend the use of Jupyter Notebooks to interact with the Python toolkit of SATRAP in a structured manner and to implement your own playbooks. 

See our ["Effective countermeasures against a group of interest" notebook](docs/notebooks/effective_measures.ipynb) and the "Quick start" in `satrap/frontend` for examples on the usage of the toolbox.

#### Integration in a Jupyter Notebook
For instance, we can try to find courses of action that mitigate any of the techniques used by the group "APT29". This function makes use of the inference rules defined in our KRS.

<img src="./docs/manual/_figures/mitigations-ntbk.png" alt="mitigation-notebook" width="85%"/>

#### Graphical explanations in TypeDB Studio
SATRAP provides textual explanations for "explanation functions" in the toolbox. As a complementary frontend, we can leverage the use of TypeDB Studio for an interactive graphical explanation of the inferred knowledge.

For example, we run the explanation function `explain_techniques_used_by_group` to understand whether and why the group "Orangeworm" (ATT&Ck id "G0071") uses the technique "Domain Groups". Then:

1. We retrieve the executed query in the native database language (TypeQL).

<img src="./docs/manual/_figures/explain-query.png" alt="Use of the CTI analysis Toolkit in a Jupyter notebook" width="75%"/>

2. We copy and run the query in TypeDB Studio to see the derivation paths as a graph.

<img src="./docs/notebooks/resources/figs/tech-g0071-paths.png" alt="derivation trace" width="85%"/>

<br/>

**NOTE:** integration of visual explanations in Jupyter Notebooks and in the development environment is considered for future releases (see the [Roadmap](#roadmap) below).

For more information on the topic, see the page on [Running investigations](./docs/manual/playbooks.md) in the user manual.

## Unit and validation tests

SATRAP comes with an extensive suite of unit tests that can be run with the script `run_tests.sh` in the development environment. Details are available in the [installation page](./docs/manual/installation.md) of the user manual.

For software validation test cases and reports, please refer to the test case specifications ([TST](https://abstractionslab.github.io/satrap-dl/docs/traceability/TST.html)) and test campaign results ([TRA](https://abstractionslab.github.io/satrap-dl/docs/traceability/TRA.html)) on our [traceability web page](https://abstractionslab.github.io/satrap-dl/docs/traceability/index.html).

## Documentation and technical specifications

The technical specifications and project documentation of SATRAP including requirements, architectural and software diagrams, test case specifications, and test reports, are accessible via our [traceability web page](https://abstractionslab.github.io/satrap-dl/docs/traceability/index.html).

## Project status
As of March 2025, this repository hosts the Alpha version of SATRAP.
For this release, efforts have largely gone into building the core components and foundations of the project, in particular, defining the knowledge base schema, implementing the ETL process and building an initial minimal set of demonstrative functions for the analysis of CTI.

In its current stage, the analytical capabilities of SATRAP can be leveraged primarily through queries written in TypeQL, the native language of TypeDB. The upcoming Beta phase mainly addresses the development and extension of the analysis capabilities of SATRAP and their exposure in the toolkit library.

**Disclaimer: use of Alpha software**

The SATRAP-DL project is in its Alpha stage and under active development; it may include incomplete features and contain bugs. This software is not intended for use in production environments.

In particular, the schema of the CTI SKB is subject to change as we need to introduce missing STIX metadata objects and deal with updated and revoked STIX objects.

## Roadmap
The most immediate tasks on the roadmap include:

* Extend and improve the elementary analysis capabilities of the Alpha release and provide a stable native Python library API.
* Define a platform-independent API (e.g., a REST API) enabling programmatic access to the services provided by SATRAP.
* Add support for ingesting STIX 2.1 custom and metadata objects.
* Transform TypeQL results into STIX2.1 objects (reverse ETL).
* Add support for automated ingestion of data from open-source threat intelligence platforms and from [IDPS-ESCAPE](https://github.com/AbstractionsLab/idps-escape), including a strategy for data maintenance.
* Create further playbooks to demonstrate the use of SATRAP for automating reasoning tasks in common CTI investigative scenarios.
* Study the integration of visual explanations in VS Code and Jupyter Notebooks

Future releases consider the integration of data from existing open-source semantic CTI repositories, e.g. [MITRE D3FEND](https://d3fend.mitre.org/https://d3fend.mitre.org/).


## License

Copyright (c) itrust Abstractions Lab and itrust consulting. All rights reserved.

SATRAP-DL is licensed under the [GNU Affero General Public License (AGPL) v3.0](LICENSE) license.

This project builds on a few ideas related to the inference rules and the analysis functionality found in [typedb-cti](https://github.com/typedb-osi/typedb-cti), an open-source project licensed under [Apache License 2.0](./satrap/assets/schema/LICENSE). During the conceptual phase of SATRAP-DL, we considered the possibility of building on top of typedb-cti, as it is in spirit close to SATRAP. However, we opted to build SATRAP largely from scratch mainly for two reasons:

- the design of typedb-cti was not compatible with the ambitions and architectural requirements of SATRAP
- typedb-cti relies on an outdated version of TypeDB that is incompatible with the latest currently maintained version 2.x. (Note: TypeDB 3.0 has been recently released and we might consider migration after achieving the main tasks on the roadmap)

## Acknowledgments

SATRAP-DL is co-funded by the Ministry of the Economy of Luxembourg, in the context of the CyFORT project.

## Contact
For more information about the project, feedback, questions or feature requests, feel free to contact us at Abstractions Lab: info@abstractionslab.lu
