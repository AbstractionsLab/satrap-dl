#!/bin/bash
# This script is used to publish specifications using Doorstop and a C5-DEC Python script for keyword replacement.
# It first runs a Python script to replace keywords in the specifications, then publishes the specifications using Doorstop, and finally runs the Python script again to undo the keyword replacement.
# Ensure the script is executable
# chmod +x ./docs/specs/c5proc-doorstop-pub.sh

# Run the Python script with "replace" argument
python ./TRA/c5-keyword.py ./TRA replace

# Navigate to the parent folder (specs) and run the doorstop publish command
doorstop publish -H all ./publish

# Run the Python script with "undo" argument
python ./TRA/c5-keyword.py ./TRA undo