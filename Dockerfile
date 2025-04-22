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
ENV user=root \
	SATRAP_FOLDER=satrap-dl

# keep separate to allow for the $user variable to be set before
ENV PROJECT_HOME=/home/${user}/${SATRAP_FOLDER}/

# Update dependencies in the Debian OS that comes with the base image
RUN apt update --fix-missing
RUN pip install --upgrade pip

# install poetry
RUN pip install "poetry==$POETRY_VERSION"
RUN poetry completions bash >> ~/.bash_completion

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
RUN apt-get autoremove -y && apt-get autoclean -y

# entry point for the deployment container run via the satrap.sh script 
ENTRYPOINT ["poetry", "run", "satrap"]
