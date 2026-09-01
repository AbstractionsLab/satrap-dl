# 1.1 (2026-09-01)

## Added

- Docker Compose based deployment artifacts for SATRAP, in line with the DECIPHER deployment paradigm: `deployment/docker-compose.satrap.yml` (TypeDB service and a build-only satrap image) and the `deployment/satrap_up.sh` and `deployment/satrap_down.sh` entrypoint scripts.
- DECIPHER analyzer supporting a network/web scanning threat scenario (`suspcious_nt_scanning`), scoring the alert IOCs (source IPs, probed URIs, user agents, HTTP methods) against MISP threat intelligence, and reporting known research or benign scanning sources as analyst context.
- DECIPHER setup tool (`decipher/tools/warninglists_mgr.py`) to list, enable and disable MISP warninglists used by the analyzers, from the API container or from the dev environment.
- `MISPCTIAnalyzer` as a base class for MISP-informed analyzers (CTI retrieval, scoring and case creation) with hooks for the scenario-specific logic.
- Identification of benign and research scanners in the MISP connector, combining warninglist lookups with matches on `research-scanner` objects.
- Filtering of the MISP events retrieved for an alert per IOC types and a minimum number of matched attributes per event.
- MISP search parameters `enforce_warninglist` and `max_values_per_type` in the DECIPHER runtime configuration.
- User manual page for the network/web scanning analyzer and a guide for developing custom analyzers.
- Unit tests for the new analyzer, the generic scenario analyzer, the MISP connector and the enrichment mixin, plus an integration test for the research-scanner search.
- Technical specifications for the suspicious network scanning scenario

## Modified

- The `misp_connector.py` and `misp_enrichment.py` modules have been enhanced with new functionality for searching and filtering.
- Default MISP search parameters are now a 7-day event timeframe and a limit of 1000 results.
- The `decipher.analyzers` package has been refactored to use the added `MISPCTIAnalyzer`.
- The SATRAP Docker image for production has been enhanced, largely reducing size and vulnerabilities.
- The security of the DECIPHER API Docker image has been improved: multi-stage build, non-root system user owning no application files, a healthcheck based on the standard library, and no `pip` in the shipped virtual environment, which removes its vendored dependency tree from the runtime stage.
- The configuration mount in the DECIPHER API service is now read-only.
- The SATRAP-DL dev image has been enhanced by fixing some bugs with shared venvs, reducing size and sharing a common base image in all 3 Dockerfiles.
- Minor restructure of `pyproject.toml` and `devcontainer.json` for a cleaner deployment
- Old scripts for building and initializing satrap have been removed.
- Documentation has been updated to reflect the new deployment mode for SATRAP.

# 1.0 (2026-05-08)

## Added

- Flowintel templates folder (`deployment/flowintel-templates/`) acting as a CyFORT incident templates repository
- User manual for DECIPHER

## Modified

- The DECIPHER REST service has been updated to rely on the new Flowintel templates repository
- The new `flowintel-templates` directory is mounted to the Flowintel container's central repository of templates
- The default FLOWINTEL_VERSION environment variable has been updated to `3.1.0` in the `docker-compose.flowintel.yml` and `env-template` files
- API unit tests to cover the updates described above have been created/updated
- Technical specs, user manuals, READMEs, code docs and traceability artifacts have been updated and enriched

## Fixed
- A bug in the deployment artifacts that caused a MISP core container to show always an unhealthy status when the misp_base_url and port were not the default ones


# 0.5.1 (2026-04-15)

## Added

- FLOWINTEL_VERSION environment variable to the `docker-compose.flowintel.yml` and `env-template` files, for specifying the version of Flowintel to deploy. Default value is `3.0.0`


# 0.5 (2026-03-19)

## Added

- Unit tests for `flowintel_connector.py` addressing the modifications to the DECIPHER incident endpoint described below

## Modified

- The DECIPHER incident endpoint has been redesigned to support scenario-agnostic case creation:
    - A scenario is no longer required as a URL parameter but passed optionally as part of the request body
    - A priority level is now required as part of the request body
- The main implementation changes concern the API, request data model and the Flowintel connector
- Technical specifications have been updated accordingly:
    - SRS-055, ARC-008, ARC-011 and SWD-009, SWD-011, SWD-013 and SWD-014
- Validation tests and reports have been updated


# 0.4 (2026-03-16)

## Added

- DECIPHER REST service for supporting the incident handling pipeline described in the README of DECIPHER
    - Support for RADAR `suspicious_login` threat scenario
    - Integration with MISP and Flowintel for IOC search and case creation
- Unit tests for the DECIPHER REST service
- Artifacts for containerized deployment of DECIPHER REST API service
- Technical specifications for the DECIPHER microservice and infrastructure
- Product presentation website

## Modified

- The project has been restructured to host both satrap and decipher Python packages with unified dependency management, testing, deployment artifacts, and documentation.
- The traceability website has been restructured and updated as per C5DEC SpecEngine v1.2


# 0.3 (2026-02-07)

## Added

- Folder to host the DECIPHER Python package, foreseen in the upcoming Beta release
- Artifacts for containerized deployment of the DECIPHER infrastructure stack (MISP, Flowintel)
- Arguments to the `satrap etl` command for setting remote download timeouts (`-mct` and `-mrt`)
- Unit tests for the new parameters added to the ETL download functionality
- A STIX 2.1 file exemplifying how to model an organization’s infrastructure
- MRSs and SRSs for DECIPHER and PyFlowintel

## Modified

- The main README has been split into dedicated READMEs per sub-project for readability
- SATRAP-DL's requirements have been updated as per the Alpha and Beta phases
- The traceability website reflects the updates to the tech specs
- The publishing engine has been updated as per the C5-DEC's latest version

## Fixed

- Rename test methods with duplicated names in `tests/file_util_test.py`


# 0.2 (2025-06-18)

## Added

- New functionality:
    - get ATT&CK groups filtering per description
    - get techniques used by all members of a list of groups
    - get mitre id using a stix id
	- search STIX object by name or alias
- Extension for spell-checking into the vscode environment
- Unit tests for the `transitive-use` rule and associated JSON files
- Function to clear a DB
- A folder `tutorials` to host material for workshops and related events
- Build image name and CLI metadata dynamically from the project toml file

## Modified

- Refactoring of the `engine` package
- Formatting functions in the `service` package have been moved to `commons`
- The functions `get_techniques_used_by` and `explain_techniques_used_by_groups` receive now a list of group IDs, for analyzing sets of groups instead of a single group
- In `init-satrap.sh`, the typedb image is downloaded only if it does not exist yet.
- Some functions in the `engine` and `service` packages have been renamed to convey their purpose more clearly
- CLI and notebooks have been adapted as per the modifications to existing functions
- New functions have been added to the "quick start" notebook

## Fixed

- A bug that returned only the last read alias instead of the full list when retrieving this value
- Improve error handling in several functions

**Note:** The `docs/codedocs` folder will be updated only at the stable release (v1.0), as the content is actively changing


# 0.1.1 (2025-04-22)

## Added

- New unit tests for the change in `file_utils.py` to cover the bug fix in this release
- An initial version of a MISP events extractor (without selection parameters)

## Modified

- Refactor the ETL orchestrator removing internal states and decoupling the dependency from a specific extractor
- Refactor the CLI for a cleaner design
- The Python API documentation in the `codedocs` folder
- README and user manual to reflect the latest changes

## Fixed

- A bug that prevented folders (e.g., logs, stixdata) from being created in the container


# 0.1 (2025-03-30)

- Initial (Alpha) release of SATRAP-DL
