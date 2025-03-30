# Installation
SATRAP offers two deployment options:

- A [command-line tool](#satrap-command-line-interface), accessible via your operating system terminal of choice
- A [containerized analysis platform](#satrap-analysis-platform-in-vs-code) within Visual Studio Code (VS Code)

To get started, clone the repository of SATRAP or download the source code from the [project's webpage](https://github.com/AbstractionsLab/satrap-dl).

```sh
git clone https://github.com/AbstractionsLab/satrap-dl.git
```

Then, proceed with one of the methods described below.

**Note:** The name of the root folder might change depending on whether the source code is cloned or downloaded. Throughout the instructions, we will assume the root folder to be `cti-analysis-platform`.

## SATRAP command-line interface
The command-line interface provides commands for setting up and populating a CTI knowledge base, and exposes a minimal set of analytical functions. We recommend its use for the ingestion of content from CTI sources and maintaining the CTI knowledge base.

### Prerequisites

* A [Docker engine](https://docs.docker.com/engine/) running

### Steps

1. In a terminal, go to the project root folder and ensure execution rights on the scripts.

    ```sh
    cd cti-analysis-platform
    chmod +x *.sh
    ```

1. Run the `init-satrap.sh` script to set up and run a TypeDB server connected to a `satrap-net` Docker network.

    ```sh
    ./init-satrap.sh
    ```

1. Run the `build-satrap.sh` script to build a Docker image for SATRAP.

    ```sh
    ./build-satrap.sh
    ```

1. Run `./satrap.sh` to display the help on the available commands or a specific command with:

    ```sh
    ./satrap.sh <command>
    ```

If the `typedb` container is stopped for any reason, it can be safely launched again by re-running the `init-satrap.sh` script.


## SATRAP analysis platform in VS Code
The recommended approach to benefit from the automated analysis functionality of the Alpha release is to deploy it in a development environment. This makes it easier to integrate SATRAP with other tools and libraries when carrying out CTI investigations.

### Prerequisites

* A [Docker engine](https://docs.docker.com/engine/) installation
* [Visual Studio Code](https://code.visualstudio.com/) (VS Code)
* the [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension for VS Code by Microsoft, to enable [development inside a container](https://code.visualstudio.com/docs/devcontainers/containers)
* the [Jupyter](https://marketplace.visualstudio.com/items?itemName=ms-toolsai.jupyter) extension for VS Code by Microsoft (required to run the notebooks)

### Steps


1. In a terminal, go to the project root folder and ensure execution rights on the scripts.

    ```sh
    cd cti-analysis-platform
    chmod +x *.sh
    ```

1. Run the `init-satrap.sh` script to set up and run a TypeDB server connected to a `satrap-net` Docker network.

    ```sh
    ./init-satrap.sh
    ```

1. Open the project folder `cti-analysis-platform` in VS Code.
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

Individual test files can be executed as regular python modules. E.g.,

```sh
python ./tests/etl/extract_test.py
```

Specific test classes and test cases can be executed as in the following examples:

```sh
python -m unittest tests.etl.extract_test.TestDownloader
```

or

```sh
python -m unittest tests.etl.load.tl_sdo_test.TestTransformLoadSDO.test_opinion_enum
```


## Quick overview of the scripts

- **init-satrap.sh**: creates the Docker network *satrap-net*, downloads an image of TypeDB v2.29.0, and creates a typedb volume for persistent storage. Then, runs TypeDB in *satrap-net* mapped to the created volume. TypeDB is exposed on port `1729`.
- **build-satrap.sh**: builds a Docker image for SATRAP.
- **satrap.sh**: creates and runs a SATRAP Docker container connected to *satrap-net*, with a volume mapping the code repository to the `/home/alab/cti-analysis-platform/satrap` folder within the SATRAP container.

<br/>

[Back to home](/docs/manual/index.md)