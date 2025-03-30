# SATRAP user manual

- [Installation](/docs/manual/installation.md)
- [Setup](/docs/manual/setup.md)
- [Quick start](/docs/manual/quick_start.md)
- [User interfaces](/docs/manual/interfaces.md)
- [Running investigations](/docs/manual/playbooks.md)
- [SATRAP fundamentals](/docs/manual/core_concepts.md)


## Overview of SATRAP

SATRAP (Semi-Automated Threat Reconnaissance and Analysis Platform) is an open-source, cross-platform software aimed at supporting computer-aided analysis of cyber threat intelligence (CTI) by leveraging automated reasoning and inference.

In short, the goal of SATRAP is to simplify analytic tasks over large amounts of information via the logical derivation of knowledge. This automated knowledge derivation (a.k.a. inference, although they are not strictly the same) is achieved by applying a set of deduction rules over information in a knowledge base.

The core of SATRAP consists of a knowledge representation system (KRS) of cyber threat intelligence (CTI), which broadly refers to a system consisting of:
* A knowledge base of cyber threat intelligence (that we call _CTI SKB_), capturing concepts and facts in the domain of CTI, such as properties between resources, threat scenarios, attacks, techniques, and tactics.
* A reasoning engine for deducing entailments on the information in the knowledge base, which can lead to the discovery of new knowledge.

The KRS of SATRAP is implemented using [TypeDB](https://typedb.com/), a polymorphic database with a native symbolic reasoning engine. The use of TypeDB allows SATRAP to implement analytic functions in the domain of CTI on top of an integrated core, where the knowledge base and the reasoning engine are natively coupled allowing for an efficient execution of inference tasks. 

The Alpha release of SATRAP comes with a predefined set of functions that demonstrate potential uses of automated reasoning capabilities applied to the CTI domain, leveraging the STIX 2.1 data model and semantic technologies.

This manual covers aspects related to the installation, setup, usage and core concepts behind the purpose and design of the Alpha version of SATRAP.

Further updates are expected as the project develops.