#!/bin/bash
echo Starting SATRAP...

# Define variables
USER=alab
CONTAINER_NAME=satrap-core
IMAGE_NAME=satrap:0.1

# Define volume mounts
CODE_VOLUME=$(pwd):/home/$USER/cti-analysis-platform

if [ "$#" -lt 1 ]
then
    # Run the Docker container with no argument: pass the -h argument to satrap
    docker run -it --rm --name $CONTAINER_NAME \
        -v $CODE_VOLUME \
        --network satrap-net \
        $IMAGE_NAME -h 
else
    # Run the Docker container with the user-specified arguments
    docker run -it --rm --name $CONTAINER_NAME \
        -v $CODE_VOLUME \
        --network satrap-net \
        $IMAGE_NAME "$@"
fi
