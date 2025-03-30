# syntax=docker/dockerfile:1
FROM python:3.11.0

# general environment settings
ENV PYTHONFAULTHANDLER=1 \
	# print immediately in stdout
	PYTHONUNBUFFERED=1 \
	PIP_NO_CACHE_DIR=off \
	PIP_DEFAULT_TIMEOUT=100 \
	POETRY_VERSION=1.8.0

# project settings
ENV user=alab \
	SATRAP_FOLDER=satrap

# keep separate to allow for the $user variable to be set before
ENV PROJECT_HOME=/home/${user}/cti-analysis-platform/

# Update dependencies in the Debian OS that comes with the base image
RUN apt update --fix-missing
RUN pip install --upgrade pip
# install satrap required tools
#RUN apt-get install -y graphviz

# Create a non-root user and set it as the current user
RUN useradd -ms /bin/bash ${user} && echo '${user} ALL=(ALL) NOPASSWD:ALL' >>/etc/sudoers
USER ${user}

# Install pipx and add the installation folder to the PATH
RUN python3 -m pip install pipx
ENV PATH="/home/${user}/.local/bin:${PATH}"

# install poetry
RUN pipx install "poetry==$POETRY_VERSION"
RUN poetry completions bash >> ~/.bash_completion

# Install Doorstop
RUN pipx install doorstop==3.0b10

# create and set the working directory (for the following commands) in the container
WORKDIR ${PROJECT_HOME}

# copy dependencies files from the current directory into the filesystem
# of the image at $PROJECT_HOME
COPY poetry.lock pyproject.toml ${PROJECT_HOME}
# copy the project files separately for build cache optimization
COPY . ${PROJECT_HOME}

# install the project's dependencies and create virtual env.
RUN poetry install

# Clean up unnecessary packages
USER root
RUN apt-get autoremove -y && apt-get autoclean -y

# Set the container's starting point running the project as the user
USER ${user}
WORKDIR ${PROJECT_HOME}${SATRAP_FOLDER}

# when a container is started...

# loading the virtual environment with 'CMD ["poetry", "shell"]' does not work 
# here as the command requires an interactive shell already running;
# this is an alternative way to launch a bash shell inside the venv
ENTRYPOINT ["poetry", "run", "bash"]

