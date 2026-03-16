# SATRAP-DL documentation

This directory contains all documentation for the SATRAP-DL project, organized into distinct categories to support different audiences and purposes.

## Documentation structure

### `codedocs/` - Generated code documentation

**Audience**: Developers

**Purpose**: Generated API reference for the SATRAP package.

### `manual/` - User and developer manuals

**Audience**: End users, system administrators, and developers

**Purpose**: Practical, task-oriented documentation explaining **HOW** to use, configure, and operate the system.

**Characteristics**:
- Narrative, tutorial-style writing
- Step-by-step procedures
- Complete configuration examples
- Frequently updated, living documentation
- Code examples and CLI references

### `notebooks/` - Interactive examples

**Audience**: Analysts and developers

**Purpose**: Jupyter notebooks demonstrating SATRAP analysis techniques and use cases.

**Contents**:
- `effective_measures.ipynb` - Analysis of effective security measures
- `threat_profiling.ipynb` - Threat profiling workflows


### `specs/` - Requirements and specifications (Doorstop)

**Audience**: System architects, requirements engineers, QA teams, auditors

**Purpose**: Formal, traceable requirements and design decisions defining **WHAT** and **WHY**.

**Contents**:
- `MRS/` - Mission requirements specifications (root)
- `SRS/` - System/software requirements specifications
- `ARC/` - Architecture requirements and constraints
- `SWD/` - Software design specifications
- `TST/` - Test case specifications
- `TRP/` - Test execution reports
- `SpecEngine/` - Custom Doorstop publishing and analysis tooling
- `publish.sh` - Publishing script

**Characteristics**:
- Formal, structured format (Doorstop YAML frontmatter)
- Focus on acceptance criteria and rationale
- Primarily diagrams, decisions, constraints
- Upward traceability links (child → parent)
- Version-controlled with reviews/approval metadata

### `traceability/` - Published requirements traceability

**Audience**: Stakeholders, auditors, project managers

**Purpose**: Generated HTML documentation showing full requirements traceability matrix.

**Generation**: Run `cd docs/specs && ./publish.sh` to regenerate from Doorstop sources.

### `website/` - Product presentation webpage
**Audience**: Stakeholders, potential users, general public

**Purpose**: High-level overview of SATRAP-DL, its value proposition, and key features.

The website is publicly accessible on GitHub Pages at [https://abstractionslab.github.io/satrap-dl/website/product-presentation.html](https://abstractionslab.github.io/satrap-dl/website/product-presentation.html).
