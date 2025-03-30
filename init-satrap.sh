#!/bin/bash

# Check if the network bridge already exists
if ! docker network ls | grep -q "satrap-net"; then
    docker network create -d bridge satrap-net
else
    echo "Network 'satrap-net' already exists."
fi

# Pull typedb image
docker pull vaticle/typedb:2.29.0

# Check if the volume already exists
if ! docker volume ls | grep -q "typedb-data"; then
    docker volume create typedb-data
else
    echo "Volume 'typedb-data' already exists."
fi

container_name="typedb"

# Stop running containers of typedb
if docker ps -a | grep -q "$container_name" && docker ps | grep -q "$container_name"; then
    echo "Stopping container '$container_name'..."
    # if previously run with this script, the container
    # is removed too due to the flag --rm (below)
    docker stop "$container_name"
fi

# Remove typedb containers if they exist (e.g. created by other means)
if docker ps -a | grep -q "$container_name"; then
    echo "Removing container '$container_name'..."
    docker rm "$container_name"
else
    echo "Container name '$container_name' available for use."
fi

# Run typedb container
if uname -s | grep -q "Darwin"; then
    echo "Detected macOS. Running container '$container_name' for AMD platform ..."
    docker run -d --rm --name typedb \
		--network=satrap-net \
		-v typedb-data:/opt/typedb-all-linux-x86_64/server/data \
		-p 1729:1729 \
		--platform linux/amd64 \
		vaticle/typedb:2.29.0    
else
    echo "Running container '$container_name'..."
    docker run -d --rm --name typedb \
		--network=satrap-net \
		-v typedb-data:/opt/typedb-all-linux-x86_64/server/data \
		-p 1729:1729 \
		vaticle/typedb:2.29.0
fi
