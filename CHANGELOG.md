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
