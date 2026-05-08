# SATRAP Fundamentals

SATRAP builds upon knowledge representation formalisms to enable the storage, management, and retrieval of information over a semantic data model.

The analytic features of SATRAP are foreseen to complement the capabilities of existing open-source CTI platforms, SIEMs and related systems. Therefore, the system is expected to have the ability to interoperate with such tools for the exchange and enrichment of information in both directions.

## Building blocks
An overview of SATRAP's main components is sketched next. For more in-depth information, check out the System Architecture documentation of SATRAP-DL in the [traceability page](https://abstractionslab.github.io/satrap-dl/traceability/index.html).

| **Component**          | **Description**                  |
|------------------------|----------------------------------|
| **CTI Knowledge representation system (KRS)** | A semantic knowledge base of CTI (CTI SKB) defined on a strongly-typed data model, plus an automated reasoning engine. Implemented on TypeDB with a STIX 2.1 conceptual data model. |
| **ETL module**         | Enables ingesting STIX 2.1-compliant data from diverse sources into the CTI SKB, including cybersecurity knowledge (e.g., MITRE ATT&CK datasets), external threat intelligence (from platforms like MISP), and behavioral data (from SIEMs, SOARs, etc.). |
| **CTI engine**         | Implements queries and inference logic for automating cyber threat intelligence analysis tasks. Leverages the reasoning engine to derive new knowledge from existing CTI data. |
| **CTI analysis Toolbox (service)** | Makes SATRAP's functionality accessible as a Python library with a predefined set of automated analysis functions for CTI investigations. |
| **User interfaces**    | A command-line interface (CLI) for knowledge base management and ETL tasks, plus Jupyter Notebooks for interactive analysis and investigation playbooks, and a native TypeDB GUI (TypeDB Studio) for direct query execution and graphical results visualization. |


## TypeDB: a suitable technology for the CTI KRS

TypeDB is an open-source database that implements a database paradigm built on a type-theoretic knowledge representation formalism called PERA (_polymorphic entity-relation-attribute_), with TypeQL as its native query language.

TypeDB implements a native inference engine that combines type-based and rule-based mechanisms for query resolution using deductive reasoning. User-defined inference rules are applied by the inference engine at query time, enabling the discovery of non-explicit information through logical entailment.

The main reasons for choosing TypeDB to host the SATRAP KRS are:

- **Expressivity**: TypeQL provides a powerful language for representing and querying complex relationships in the CTI domain
- **Accessibility**: The intuitive query language is accessible to a larger programming community, important for maintenance and extensibility
- **Integrated reasoning**: The knowledge base and reasoning engine are encapsulated in one platform, which typically enables performance optimization and the implementation of efficient data management strategies
- **Formal foundation**: The novel PERA data model paradigm provides sound theoretical foundations built on lessons learned from existing database paradigms
- **Flexible inference**: The combination of open and closed world assumptions when performing inference and constraint satisfaction

## Knowledge Representation System for CTI

The CTI knowledge base represents a conceptual data model expressed through a formal representation that mathematically captures various relations: properties between resources, threat scenarios, attacks, techniques, and tactics.

### CTI conceptual data model

SATRAP's data model is aligned with the STIX 2.1 specification, the industry standard for representing and exchanging cyber threat intelligence information. The STIX 2.1 specifications are formalized in TypeQL within SATRAP's schema files (`cti-skb-types.tql`).

**Limitations**: STIX custom objects are currently not supported in SATRAP. All data must conform to standard STIX 2.1 domain objects, cyber observables, and relationship objects.

### Core STIX objects

SATRAP uses standard STIX 2.1 objects to represent CTI data. Key objects include:

- **Indicator**: Represents a pattern that can detect suspicious or malicious activity
- **Attack Pattern**: Describes a specific way an adversary may attempt to compromise a target
- **Intrusion Set**: Represents a group of adversaries sharing common goals, tactics, techniques, and procedures (TTPs)
- **Malware**: Describes malicious code or programs
- **Tool**: Represents legitimate software that can be used for attacks
- **Campaign**: Represents a series of attacks over time
- **Course of Action**: Represents a mitigation or defense strategy

All STIX domain objects and relationship objects require a `spec_version` property to ensure appropriate validation.

### Relationships

Relationships in STIX link different objects together. Common relationships include:

- **Uses**: Links an entity (e.g., intrusion set) to resources it uses (e.g., attack patterns, malware, tools)
- **Mitigates**: Links a course of action to the attack patterns it mitigates
- **Attributed-to**: Links behaviors or infrastructure to attributed threat actors
- **Targets**: Indicates which entities or victims are targeted

### Data sources

The CTI knowledge base can be populated with data from:

- **Cybersecurity knowledge**: Datasets from MITRE (CVE, CWE, CAPEC, ATT&CK, D3FEND) and Kill Chain phases
- **External threat intelligence**: Shared CTI from platforms like MISP, OSINT sources, and threat reports
- **Internal CTI**: Internally documented attack events and investigative findings
- **Behavioral data**: Network alerts, terminal alerts, and logs from SIEMs, SOARs, and IDS/IPS systems (e.g., IDPS-ESCAPE, Wazuh, Suricata)

## ETL pipeline

SATRAP ingests data through an extract-transform-load (ETL) pipeline designed for STIX 2.1 data:

1. **Extraction**: Data is extracted from diverse sources in STIX 2.1 format or converted to STIX 2.1
2. **Transformation**: STIX objects are validated, normalized, and transformed into TypeDB insertion queries for entities and relationships
3. **Loading**: The insertion queries are executed to insert data into the TypeDB knowledge base

The ETL module handles:
- Validation of STIX 2.1 compliance
- Relationship mapping and consistency
- Schema-compliant data loading

## CTI analysis via automated reasoning

SATRAP's inference engine applies predefined rules to derive new relationships. For example:

- **Transitive use**: If group A uses malware B, and malware B uses technique C, then group A uses technique C
- **Usage via attribution**: If an identity X is attributed to threat actor Y, and X uses malware Z, then Y uses malware Z (through X)

These inferred relationships are computed at query time and returned alongside explicit facts, enabling analysts to discover non-obvious connections.

The CTI engine provides query functionality for automated reasoning over the knowledge base. Analysis is performed by:

1. Formulating analysis questions as TypeQL queries or leveraging pre-built analysis functions
2. Executing queries that retrieve explicit facts and trigger inference rules
3. Obtaining results that include derived knowledge along with explanations of the logical derivation

The CTIanalysisToolbox provides predefined analysis functions, such as:

- Finding all techniques used by a specific threat actor group
- Identifying mitigation strategies relevant to an actor's techniques
- Discovering indirect relationships between entities through inference chains

All results include traceability information showing how the knowledge was derived, supporting explainable CTI analysis.



<br/>

[Back to home](/docs/manual/satrap/README.md)