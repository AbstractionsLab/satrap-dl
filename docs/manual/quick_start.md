# Getting Started

To benefit from the analysis functionality of SATRAP that enables automated reasoning, we recommend its [use in Visual Studio Code](/docs/manual/installation.md#satrap-analysis-platform-in-vs-code). Once the project is open, follow these simple steps.

**Create and populate a CTI knowledge base**

Set up the SATRAP CTI SKB with the [default parameters](#configuration-parameters) from the VS Code terminal. We assume you have run `poetry shell` before running the commands below, otherwise the commands run from the VS Code terminal should be preceded by `poetry run`, e.g., `satrap run` -> `poetry run satrap setup`.

1. Create a CTI SKB called `satrap-skb-alpha`.
    ```sh
    satrap setup
    ```
1. Run the ETL process to ingest the latest version of the [MITRE ATT&CK Enterprise](https://github.com/mitre-attack/attack-stix-data) dataset.
    ```sh
    satrap etl 
    ```

**Note**: The same commands can be run from a terminal session (shell), using our `./satrap.sh` script, e.g., `satrap setup` -> `./satrap.sh setup`.

**Ingest additional data sets**

You can ingest the data sets of MITRE ATT&CK Mobile and MITRE ATT&CK ICS by running:

```sh
satrap etl -src $(python -c "from satrap.settings import MITRE_ATTACK_MOBILE; print(MITRE_ATTACK_MOBILE)")
```
```sh
satrap etl -src $(python -c "from satrap.settings import MITRE_ATTACK_ICS; print(MITRE_ATTACK_ICS)")
```

Alternatively, set the URL of a STIX 2.1 data source in the `extract_src` parameter of the [configuration file](/docs/manual/setup.md) to ingest data from other sources.

**Execute sample functions using the Python CTIAnalysisToolbox**:

Select and run one of our [sample notebooks](/docs/manual/playbooks.md) to learn how to use the functions of SATRAP and how to apply them on a CTI investigation case.

<br/>

[Back to home](/docs/manual/index.md)