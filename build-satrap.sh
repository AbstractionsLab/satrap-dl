#!/bin/bash
# This script cleans and rebuilds an image of satrap

# Create the image name with the project name and version from pyproject.toml
# -F '"' sets the field separator in the toml file
# For lines starting with 'name' or 'version', replace single and/or double quotes in the 2nd token ($2)
# with an empty string and store them in an associative array v
# Then, print the values in the format name:version
IMAGE_NAME=$(awk -F ' *= *' \
            '/^(name|version)/ {gsub(/["'\'']/,"",$2); v[$1]=$2} END \
            {print v["name"] ":" v["version"]}' \
            pyproject.toml)

# remove all containers of the image and the image itself
docker ps -a -q --filter ancestor=$IMAGE_NAME | xargs --no-run-if-empty docker rm
echo "Removing previous instances of image $IMAGE_NAME..."
docker rmi $IMAGE_NAME

# build an image with the same name
#docker build --progress=plain --no-cache -t $IMAGE_NAME .
echo "(Re)building image ..."
docker build -t $IMAGE_NAME .

echo "Image $IMAGE_NAME built successfully."
