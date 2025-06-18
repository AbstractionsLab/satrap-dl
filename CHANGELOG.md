
# 0.1.2 (2025-06-18)

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

**Note:** The `docs/codedocs` folder will be updated only at the Beta release, as the content is actively changing

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
