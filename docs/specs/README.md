# Technical specifications aimed at traceability

This folder contains the authoritative, traceable specifications for SATRAP-DL, managed with Doorstop and enhanced by C5-DEC-style tooling in SpecEngine. The technical specifications define what the system must do, why it matters, and how requirement coverage is demonstrated through architecture, design, and executed tests.

## Table of contents

- [What lives here](#what-lives-here)
- [Doorstop hierarchy](#doorstop-hierarchy)
- [Conventions](#conventions)
- [Working with items](#working-with-items)
- [When to use which document](#when-to-use-which-document)
- [Custom tooling scripts](#custom-tooling-scripts)
- [Publishing](#publishing)

## What lives here

| Path | Document type | Role in hierarchy |
|------|--------------|-------------------|
| `MRS/` | Mission requirements specifications | Root of the tree |
| `SRS/` | System/software requirements specifications | Child of MRS |
| `ARC/` | Architecture requirements and constraints | Child of SRS |
| `SWD/` | Software design | Child of ARC |
| `TST/` | Test case specifications | Child of SRS |
| `TRA/` | Test execution reports | Child of TST |
| `SpecEngine/` | Python tooling for publishing, analysis, and graph generation | See [Custom tooling scripts](#custom-tooling-scripts) |


## Doorstop hierarchy

```
MRS (root) -> SRS -> ARC -> SWD
                 -> TST -> TRA
```

Links are upward-only (child -> parent). Adding downward links or cross-level links can break publishing and may trigger recursion errors.

## Conventions

- Numbering: three digits per prefix (for example, `SRS-001`) as configured in each `.doorstop.yml`.
- Format: markdown items with YAML frontmatter followed by a markdown body.
- Parent rule: each document links only to its direct parent document (for example, SRS -> MRS, ARC -> SRS, TST -> SRS, TRA -> TST).
- Assets: place supporting files per document under its local `assets/` folder.
- Diagrams: Mermaid blocks are supported and automatically rendered during publishing.
- Review hashes: Doorstop fingerprints change when reviewed fields or content change; re-review modified items.
- Named items: group items such as `MRS-SATRAP`, `SRS-SATRAP`, and similar non-numeric IDs may be excluded from numeric statistics unless explicitly included.

## Working with items

```bash
# Validate the tree
poetry run doorstop

# Add a new item (auto UID)
poetry run doorstop add srs

# Link child to parent (upward-only)
poetry run doorstop link TST-001 SRS-046

# Review an item after editing it
poetry run doorstop review SRS-001
```

## When to use which document

| Document | Use for |
|----------|---------|
| MRS | Mission and business needs, priority, and value |
| SRS | System/software requirements and acceptance intent |
| ARC | Architectural constraints and structural decisions linked to requirements |
| SWD | Detailed software design and implementation-oriented design content |
| TST | Test case definitions and execution procedure |
| TRA | Executed test evidence, results, and defect categorization |

For detailed rules and examples, see each folder's `.doorstop.yml`.

## Custom tooling scripts

All scripts live under `SpecEngine/`. The top-level `publish.sh` orchestrates the end-to-end pipeline.

| Script | Purpose |
|--------|---------|
| `publish.sh` | Runs the full publish sequence (keyword replacement, Mermaid rendering, Doorstop publish, traceability stats, browser, linkify, graph) |
| `SpecEngine/c5publish.py` | Runs Doorstop HTML publishing, applies Bootstrap styling patches, linkifies item IDs, and injects links to generated reports |
| `SpecEngine/c5-keyword.py` | Replaces and restores `?c5-defect-X` shorthand keywords in report files (currently applied to TRA in `publish.sh`) |
| `SpecEngine/c5mermaid.py` | Renders fenced Mermaid blocks to images for publishing, with undo mode to restore editable Mermaid source |
| `SpecEngine/c5traceability.py` | Computes coverage metrics from Doorstop traceability CSV and can generate an HTML report |
| `SpecEngine/c5browser.py` | Generates an interactive browser (`items_browser.html`) with sortable/filterable tables per document type |
| `SpecEngine/c5graph.py` | Generates an interactive Cytoscape.js dependency graph (`specs-graph.html`) of item links |
| `SpecEngine/prune_bad_links.py` | Removes invalid Doorstop `links:` entries that violate direct-parent constraints |
| `SpecEngine/doorstop_yml_to_md.py` | Migration helper from legacy YAML items (`.yml`) to Markdown-with-frontmatter (`.md`) |

## Publishing

```bash
cd docs/specs
./publish.sh
```

`publish.sh` runs this pipeline:

1. `SpecEngine/c5-keyword.py` replace in TRA files
2. `SpecEngine/c5mermaid.py` render Mermaid blocks for publication
3. `SpecEngine/c5publish.py` publish Doorstop HTML to `docs/publish/`
4. `SpecEngine/c5-keyword.py` undo in TRA files
5. `SpecEngine/c5mermaid.py . undo` restore editable Mermaid blocks
6. `SpecEngine/c5traceability.py --html` compute and publish coverage statistics
7. `SpecEngine/c5browser.py` generate interactive item browser
8. `SpecEngine/c5publish.py --linkify-only` re-linkify all HTML pages
9. `SpecEngine/c5graph.py` generate interactive traceability graph


See the README of the SpecEngine for details on each of the Python scripts used in  `publish.sh`.
