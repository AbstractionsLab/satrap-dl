#!/bin/bash

# Usage: ./run_tests.sh [satrap|decipher]
# No argument: runs all tests
# satrap: runs only SATRAP tests
# decipher: runs only DECIPHER tests

PACKAGE=${1:-all}

case "$PACKAGE" in
    satrap)
        echo "Running SATRAP tests only..."
        python -m unittest discover -s tests/satrap -t . -p '*test.py'
        ;;
    decipher)
        echo "Running DECIPHER tests only..."
        python -m unittest discover -s tests/decipher -t . -p '*test.py'
        ;;
    all)
        echo "Running all tests (SATRAP + DECIPHER)..."
        python -m unittest discover -s tests -t . -p '*test.py'
        ;;
    *)
        echo "Invalid argument '$PACKAGE'"
        echo "Usage: $0 [satrap|decipher]"
        echo "  No argument: runs all tests"
        echo "  satrap:      runs only SATRAP tests"
        echo "  decipher:    runs only DECIPHER tests"
        exit 1
        ;;
esac
