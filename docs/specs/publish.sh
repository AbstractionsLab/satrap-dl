#!/bin/bash

# This script is used to publish specifications using Doorstop 
# and a C5-DEC Python script for keyword replacement.
# First, it runs a Python script to replace keywords in the specifications, 
# then it publishes the specifications using Doorstop, and finally 
# runs the Python script again to undo the keyword replacement.
#
# Ensure the script is executable
# chmod +x ./docs/specs/publish.sh


echo Usage guide:
echo ---
echo ./publish.sh
echo ---

# Run c5 keyword replacement with "replace" argument
python ./c5-keyword.py ./TRA replace
# python ./c5-keyword.py ./trb replace
# python ./c5-keyword.py ./trs replace

# Publish to a local file ignored by GIT
python ./c5publish.py
# Publish directly to the '/docs/traceability' folder
# python ./c5publish.py --trace

# Run c5 keyword replacement with "undo" argument
python ./c5-keyword.py ./TRA undo
# python ./c5-keyword.py ./trb undo
# python ./c5-keyword.py ./trs undo
