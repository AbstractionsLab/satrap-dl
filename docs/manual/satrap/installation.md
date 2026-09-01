# Installation
SATRAP offers two deployment options:

- A [command-line tool](#satrap-command-line-interface), accessible via your operating system terminal of choice
- A [containerized analysis platform](#satrap-analysis-platform-in-vs-code) within Visual Studio Code (VS Code)

To get started, clone the repository of SATRAP or download the source code from the [project's webpage](https://github.com/AbstractionsLab/satrap-dl).

```sh
git clone https://github.com/AbstractionsLab/satrap-dl.git
```

Then, proceed with one of the methods described below.

For further details on the deployment scripts, see the [SATRAP deployment reference](./deployment_artifacts.md).

**Note:** The name of the root folder might change depending on whether the source code is cloned or downloaded. Throughout the instructions, we will assume the root folder to be `satrap-dl`.

## SATRAP command-line interface
The command-line interface provides commands for setting up and populating a CTI knowledge base, and exposes a minimal set of analytical functions. We recommend its use for the ingestion of content from CTI sources and maintaining the CTI knowledge base.

### Prerequisites

* A [Docker engine](https://docs.docker.com/engine/) running

### Steps

1. In a terminal, go to the project root folder and ensure execution rights on the scripts.

    ```sh
    cd satrap-dl
    chmod +x satrap.sh deployment/satrap_up.sh deployment/satrap_down.sh
    ```

1. From the `deployment` directory, run `satrap_up.sh` to bring up a TypeDB server (connected to the `satrap-net` Docker network, with a persistent `typedb-data` volume) and build the SATRAP Docker image.

    ```sh
    cd deployment
    ./satrap_up.sh
    cd ..
    ```

    By default the TypeDB server is published on host port `1729` (for access from TypeDB Studio). To use a different host port, use the `-p <port>` parameter. E.g.:

    ```sh
    ./satrap_up.sh -p 1730
    ```

1. From the project root folder, run `./satrap.sh` to display the help on the available commands, or a specific command with:

    ```sh
    ./satrap.sh <command>
    ```


## SATRAP analysis platform in VS Code
The recommended approach to benefit from the automated analysis functionality of the Python toolbox is to deploy it in a development environment. This makes it easier to integrate SATRAP with other tools and libraries when carrying out CTI investigations.

### Prerequisites

* A [Docker engine](https://docs.docker.com/engine/) installation
* [Visual Studio Code](https://code.visualstudio.com/) (VS Code)
* the [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension for VS Code by Microsoft, to enable [development inside a container](https://code.visualstudio.com/docs/devcontainers/containers)

### Steps


1. In a terminal, go to the deployment folder and ensure execution rights on the SATRAP scripts.

    ```sh
    cd satrap-dl/deployment
    chmod +x satrap_up.sh satrap_down.sh
    ```

1. Use `satrap_up.sh` to set up and run a TypeDB server connected to the `satrap-net` Docker network.

    ```sh
    ./satrap_up.sh --typedb
    ```

1. Open the project folder `satrap-dl` in VS Code.
1. To run the project inside a Docker container, select "Reopen in Container" in the notification that pops up when opening the project in VS Code. Alternatively, run the command "Dev Containers: Reopen in Container" in the VS Code command palette (`cmd/ctrl + shift + p`).
1. In the VS Code terminal, install the project dependencies and the project in the container:

    ```sh
    poetry install
    ```

1. Then, activate a virtual environment:
    
    ```sh
    poetry shell
    ```

1. Run satrap commands in the terminal simply using:
    
    ```sh
    satrap <command>
    ```

Here, you can also run the Jupyter Notebooks included at `docs/notebooks` and `satrap/frontend` or create your own from scratch.

**Hint:** Make sure that the Python interpreter of the environment created by poetry is selected. This can be checked and changed on the right side of the Status Bar in the lower right corner of VS Code.

### Running unit tests

All the unit tests of the project can be run from the root folder with

```sh
./run_tests.sh
```

Individual test modules can be run using the `unittest` module. For example:

```sh
python -m unittest tests.satrap.file_util_test
```

Specific test classes and test cases can be executed as in the following examples:

```sh
python -m unittest tests.satrap.etl.extract.extract_test.TestDownloader
```

or

```sh
python -m unittest tests.satrap.etl.load.tl_sdo_test.TestTransformLoadSDO.test_opinion_enum
```

The `typedb` service can be safely stopped with and restarted with `deployment/satrap_up.sh --typedb`.

## Bringing down SATRAP

The deployment stack of SATRAP (TypeDB + SATRAP Docker image) can be stopped and optionally removed using the `deployment/satrap_down.sh` script.

To stop TypeDB and remove the `satrap-net` network:

```sh
./satrap_down.sh
```

To also remove the typedb-data named volume (which deletes the knowledge base) and the satrap image:

```sh
./satrap_down.sh --purge
```

<br/>

[Back to home](/docs/manual/satrap/README.md)