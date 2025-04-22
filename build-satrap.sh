#!/bin/bash
# This script cleans and rebuilds an image of satrap
IMAGE_NAME=satrap:0.1

# remove all containers of the image "satrap:0.1" and the image
docker ps -a -q --filter ancestor=$IMAGE_NAME | xargs --no-run-if-empty docker rm
echo "Removing previous instances of image $IMAGE_NAME..."
docker rmi $IMAGE_NAME

# build an image with the same name
#docker build --progress=plain --no-cache -t satrap:0.1 .
echo "(Re)building image ..."
docker build -t $IMAGE_NAME .

echo "Image $IMAGE_NAME built successfully."
