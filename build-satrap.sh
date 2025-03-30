#!/bin/bash
# This script cleans and rebuilds an image of satrap

# remove all containers of the image "satrap:0.1" and the image
docker ps -a -q --filter ancestor=satrap:0.1 | xargs docker rm
docker rmi satrap:0.1

# build an image with the same name
#docker build --progress=plain --no-cache -t satrap:0.1 .
docker build -t satrap:0.1 .
