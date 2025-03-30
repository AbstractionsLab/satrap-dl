# Setup

### Configuring the execution parameters

The default execution parameters of SATRAP are defined in the configuration file `satrap/assets/satrap_params.yml`.
Unless otherwise specified, e.g. by command arguments, the CLI and the Python toolbox run using this settings.

The configuration file contains the following parameters grouped by categories based on their scope:


```yaml
typedb:
  host: "typedb"
  port: "1729"
  db_name: "satrap-skb-alpha"

log:
  # dev, testing, prod (see user manual)
  env: "prod"

etl:
  # url of stix2.1 data source
  # extract_src: "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"

tl:
  # local path of a stix2.1 file
  # transform_src: ""
```
These parameters are explained next.

**typedb**: TypeDB server settings; if not provided, the indicated default values are assigned.

- **host**: The hostname or IP address of the TypeDB instance. The default value `"typedb"` corresponds to the name of the typedb container in the `satrap-net` Docker network.  
- **port**: The port number for connecting to TypeDB. Default is `"1729"`.  
- **db_name**: The name of the database to be used. Default is `"satrap-skb-alpha"`.  

**log**: SATRAP has the following predefined logging environments.

| Environment | Logging level | Output file name       |
|-------------|---------------|--------------------------|
| dev         | DEBUG         | `debug.log`             |
| testing     | TESTING       | Console                 |
| prod        | INFO          | `info.log`              |
| None/Other  | ERROR         | `error.log`             |

The output file is stored by default in the folder `satrap/assets/logs/<date>`.
- **env**: Specifies the logging environment. The possible values are those defined above.

**etl**: default values for arguments of the `satrap etl` command
- **extract_src**: The URL of the STIX 2.1 data source for the extraction process. This is the default value for the `-src` argument of the `etl` command. If not provided, it defaults to the MITRE ATT&CK [stix2.1 dataset](https://github.com/mitre-attack/attack-stix-data) of the Enterprise domain.

  The value commented as an example in the file snippet above points to the MITRE ATT&CK dataset of the industrial control systems (ICS) domain. 

**tl**: default values for the arguments of the `satrap tl` command
- **transform_src**: The path of a STIX 2.1 local file to be used as the source of the transformation process. This is the default value for the `-f` argument of the `tl` command, set to `tests/data/test-sample.json` if not provided.

More configuration options are available in the file `satrap/settings.py`.

<br/>

[Back to home](/docs/manual/index.md)