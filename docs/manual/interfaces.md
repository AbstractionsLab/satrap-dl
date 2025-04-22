# SATRAP user interfaces

SATRAP offers a suite of built-in and suggested third-party open source interfaces providing complementary features for managing the CTI SKB, programmatic access to analytic functions, visual explanations of inferred knowledge and running native queries over the CTI SKB.

## SATRAP CLI for CTI SKB management

The `satrap` command is the main entry point for interacting with the SATRAP system via the command-line interface. It provides a set of subcommands to manage the Cyber Threat Intelligence Semantic Knowledge Base (CTI SKB), perform ETL (Extract, Transform, Load) operations, and execute various simple tasks that support CTI analysis.

The default parameters are taken from the [configuration file](/docs/manual/setup.md).
To run a subcommand on a different endpoint and database without modifying the file, run:
```sh
satrap -ep <endpoint> -db <db_name> SUBCOMMAND [ARGS]
```
Use `-h` for more information on the options.

### Subcommands for data management
The `-db` option of these commands overwrites the same option of `satrap`.

**`setup`** 
Creates a fresh semantic knowledge base for SATRAP (the CTI SKB).

**Options**:
  - `-db`, `--database`: Specifies the name of the database where data is to be inserted. Default value: parameter `db_name` in the configuration file.
  - `-d`, `--delete`: Deletes the database if it exists and recreates it.
  - `-tm`, `--testmode`: Creates a test database with the name defined by the variable `DB_NAME_TST` in `settings.py`. Existing instances are overwritten.

**Examples:**
```sh
satrap setup -db cti-skb -d
```

**`etl`**
Ingests data from an external source, transforms it and then loads it into the CTI SKB of SATRAP. (_Note: Future releases will include a way to load several files, configurable from the configuration file._)

**Options**:
  - `-src`: Specifies the path or URL of a STIX2.1-compliant data source.
  Default value: parameter `extract_src` in the configuration file.
  - `-db`, `--database`: Specifies the database where data is to be inserted. Default value: parameter `db_name` in the configuration file.
  - `-x`, `--xmode`: Specifies the type of extraction. The (default) value `1` is used for downloading a STIX 2.1 file from a URL, and `2` for ingesting events from a MISP instance.
  - `-tm`, `--testmode`: Extracts the dataset of a sample STIX 2.1 file and loads the data into the test database created by `satrap setup -tm`.

**Example:**
```sh
satrap setup etl -tm
```

**`tl`**
Transforms data from a given STIX 2.1 file and loads it into the CTI SKB of SATRAP.

**Options**:
  - `-f`, `--file`: Specifies the path of a STIX 2.1 file to be transformed and loaded. Default: `TRANSFORM_SRC_CLI` in "settings.py"; currently it points to an example from the [Oasis open repository of STIX](https://github.com/oasis-open/cti-stix2-json-schemas/tree/master/examples).
  - `-db`, `--database`: Specifies the database where data is to be inserted. Default value: parameter `db_name` in the configuration file.

**Example:**
```sh
satrap tl -db cti-test
```

### Subcommands supporting CTI analysis
The following subcommands can assist with elementary tasks of CTI analysis.

> **NOTE:** The CLI is mainly intended for setting up the CTI SKB; the commands in this section show a quick overview of data in the CTI SKB. For a richer set of commands supporting analytic tasks with automated reasoning, consider using the Python Toolkit.
>
> Recall also that this is the Alpha release of SATRAP. The development of more and richer functions is planned for future releases.


| Command       |Description                                                       |
|---------------|------------------------------------------------------------------|
| `info_mitre`  | Retrieves information about a specific MITRE ATT&CK element (e.g., technique, group, software).  | 
| `mitigations` | Displays the mitigations specified in MITRE ATT&CK.              |
| `rules`       | Displays the names of the inference rules defined on the CTI SKB.|
| `search`      | Searches for a STIX object in the CTI SKB using its STIX ID.     |
| `stats`       | Provides statistics on existing STIX domain objects (SDOs).      |
| `techniques`  | Provides insights into the number of groups that use of MITRE ATT&CK techniques.  |

### Parameters:

 **`info_mitre`** 
  - `id`: The MITRE ATT&CK ID of the element to retrieve information about.

**Example**
```sh
satrap info_mitre C0034
```

**`search`**
  - `stix_id`: The STIX ID of the object to search for.

**`techniques`** 

**Options**:
- `-i`, `--infer`: Enables the inference engine.
- `-min`: Shows only techniques used in at least this number of intrusion sets.
- `-max`: Shows only techniques used in at most this number of intrusion sets.
- `--sort`: Specifies the sort order (`desc` by default or `asc`).
- `--limit`: Limits the number of techniques shown.
- `--norevoked`: Excludes revoked STIX entities.

**Example:**
Display all the techniques used by at least 70 groups and at most 100, obtained using inference and sorted by increasing number of usage.
```sh
satrap techniques -min 70 -max 100 -i --sort asc
```


## Visual Studio Code as an analysis workbench

Visual Studio Code provides a well-equipped environment for carrying out structured CTI analysis workflows and managing SATRAP resources. Besides the typical use as a development environment, it offers a couple of advantages as an analysis workbench:

- **Integrated terminal**: We can run the SATRAP CLI in the integrated terminal taking advantage of having access to the code. For instance, we can execute the ETL process with parameters defined in the code:

    ```sh
    satrap etl -src $(python -c "from satrap.settings import MITRE_ATTACK_ICS; print(MITRE_ATTACK_ICS)")
    ```

- **Jupyter Notebooks**: For a structured and longer analysis, you can integrate the Python Toolkit of SATRAP in a Jupyter Notebook with other related libraries, such as [PyMISP](https://github.com/MISP/PyMISP), [mitreattack-python](https://github.com/mitre-attack/mitreattack-python) or the [OpenCTI Python client](https://github.com/OpenCTI-Platform/client-python) to enrich your analysis framework and improve the investigation process.

To use the Python Toolbox of SATRAP, simply import it and initialize it with the appropriate database settings:

```py
from satrap.service.satrap_analysis import CTIanalysisToolbox
from satrap.settings import TYPEDB_SERVER_ADDRESS, DB_NAME

satrap = CTIanalysisToolbox(TYPEDB_SERVER_ADDRESS, DB_NAME)
```

See our Jupyter Notebook [examples](./playbooks.md).

## TypeDB Studio for visualizing inference explanations

The textual explanation output by the explanation functions of the Python Toolbox is informative, however, we recommend using SATRAP in tandem with the native GUI of TypeDB (TypeDB Studio) to obtain an interactive graphical explanation of the derivations.


Assuming that TypeDB Studio is running and connected to an appropriate CTI SKB:

1. Extract the TypeQL query that was used to obtain an explanation; for example, the techniques associated to a group.
```py
reason = satrap.explain_related_techniques("ZIRCONIUM", "T1059.006")
print(reason.query)
```
2. Copy the query in the editor of TypeDB Studio.
3. Enable the options: 'data', 'read', 'snapshot, 'infer' and'explain' on the toolbar at the top.
4. Run the query (`play` button at the top).
5. The result is shown in the Graph Visualizer area. Inferred relations are highlighted in green; to see the explanation, double-click on the highlighted result.

Details on the installation and use of TypeDB Studio are available in the official [TypeDB documentation](https://typedb.com/docs/manual/2.x/studio#_inference).

## TypeDB interfaces for querying the CTI SKB in the native TypeQL

SATRAP allows the creation of a semantic knowledge base for cyber threat intelligence.

We encourage you to go further and experiment with your own queries and define your own rules directly in the CTI SKB. TypeDB has comprehensive [documentation](https://typedb.com/docs/home/2.x/) and a [TypeDB Academy](https://typedb.com/docs/academy/2.x/) to guide you on this task.

To get started, you can use the queries output by the explanation functions in our Python Toolbox or those defined in the CTI engine.

<br/>

[Back to home](/docs/manual/index.md)