# DECIPHER user manual


This manual covers aspects related to the installation, configuration, usage and core concepts behind the purpose of DECIPHER.

## Content

- [Installation](/docs/manual/decipher/installation.md)
  - [DECIPHER stack deployment](/docs/manual/decipher/deployment.md)
- [Configuration](/docs/manual/decipher/configuration.md)
- [Quick start](/docs/manual/decipher/quick_start.md)
- [Analyzers](/docs/manual/decipher/analyzers.md)
  - [Suspicious login analyzer](/docs/manual/decipher/susp_login_analyzer.md)
  - [Suspicious web scanning analyzer](/docs/manual/decipher/web_scn_analyzer.md)
  - [Creating a custom analyzer](/docs/manual/decipher/custom_analyzer.md)
- [DECIPHER fundamentals](/docs/manual/decipher/core_concepts.md)
- [DECIPHER and RADAR integration](/docs/manual/decipher/radar-integration.md)

## Overview of DECIPHER

DECIPHER (**D**etection, **E**nrichment, **C**orrelation, **I**ncident, **P**laybook, **H**andling, **E**scalation and **R**ecovery) is a subsystem of SATRAP-DL aimed at enabling automated workflows for handling security incidents informed by cyber threat intelligence (CTI) and leveraging open-source tools.

DECIPHER implements a REST-based service that analyzes security alerts from predefined threat scenarios and creates prioritized cases based on a computed threat severity score. The system bridges the gap between security detection (via Wazuh or similar SIEMs) and incident response platforms (via Flowintel), enriching alerts with CTI intelligence from MISP.

See the [DECIPHER README](/decipher/README.md) for an overview of the key capabilities. 

### Workflow overview

The typical DECIPHER workflow follows these steps:

1. Detect and create alerts in your SIEM for the selected threat scenario
2. Enrich by searching for CTI related to the alert indicators of compromise (IOCs) in MISP
3. Correlate and determine a CTI severity score via automated analysis on the enriched alerts
4. Escalate incidents to prioritized cases in Flowintel
5. Add relevant playbooks to the case for further analysis
6. Recovery actions are left to the judgment of incident responders
