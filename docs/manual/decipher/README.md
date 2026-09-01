# DECIPHER user manual

- [Installation](/docs/manual/decipher/installation.md)
- [Configuration](/docs/manual/decipher/configuration.md)
- [Quick start](/docs/manual/decipher/quick_start.md)
- [Analyzers](/docs/manual/decipher/analyzers.md)
  - [Suspicious login analyzer](/docs/manual/decipher/susp_login_analyzer.md)
  - [Suspicious web scanning analyzer](/docs/manual/decipher/web_scn_analyzer.md)
  - [Creating a custom analyzer](/docs/manual/decipher/custom_analyzer.md)
- [DECIPHER fundamentals](/docs/manual/decipher/core_concepts.md)
- [Deployment stack reference](/docs/manual/decipher/deployment.md)

## Overview of DECIPHER

DECIPHER (**D**etection, **E**nrichment, **C**orrelation, **I**ncident, **P**laybook, **H**andling, **E**scalation and **R**ecovery) is a subsystem of SATRAP-DL aimed at enabling automated workflows for handling security incidents informed by cyber threat intelligence (CTI) and leveraging open-source tools.

DECIPHER implements a REST-based service that analyzes security alerts from predefined threat scenarios and creates prioritized cases based on a computed threat severity score. The system bridges the gap between security detection (via Wazuh or similar SIEMs) and incident response platforms (via Flowintel), enriching alerts with CTI intelligence from MISP.

### Key capabilities

- **Extensible REST API**: Analysis endpoints for diverse threat scenarios. Two scenarios ship with the service, suspicious login and suspicious web scanning, and new ones are added by subclassing the shared analysis pipeline
- **MISP enrichment**: Real-time indicator of compromise (IOC) search and threat intelligence retrieval
- **Threat scoring**: Configurable severity score calculation based on threat level, confidence, sightings, and threat identification tags
- **Case management**: Automated case creation in Flowintel with analysis reports and priority tags
- **Auto-reloadable configuration**: Configuration changes take effect without restarting the service
- **Containerized deployment**: Single-command deployment using Docker Compose

### Workflow overview

The typical DECIPHER workflow follows these steps:

1. Detect and create alerts in your SIEM for the selected threat scenario
2. Enrich by searching for CTI related to the alert indicators of compromise (IOCs) in MISP
3. Correlate and determine a CTI severity score via automated analysis on the enriched alerts
4. Escalate incidents to prioritized cases in Flowintel
5. Add relevant playbooks to the case for further analysis
6. Recovery actions are left to the judgment of incident responders

This manual covers aspects related to the installation, configuration, usage and core concepts behind the purpose and design of DECIPHER. We recommend using this manual as a complement of the DECIPHER READMEs, which provide more technical details on specific topics, e.g., deployment of the infrastructure stack.