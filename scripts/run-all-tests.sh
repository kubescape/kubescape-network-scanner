#!/bin/bash

# Check that the command line binary exists
COMMAND_LINE_BINARY=./kubescape-network-scanner
if ! [ -x "$(command -v $COMMAND_LINE_BINARY)" ]; then
  echo "Error: $COMMAND_LINE_BINARY is not installed." >&2
  exit 1
fi

# Check that kubectl is available
if ! [ -x "$(command -v kubectl)" ]; then
  echo "Error: kubectl is not installed." >&2
  exit 1
fi

# Check that cluster is running
if ! kubectl cluster-info > /dev/null 2>&1; then
  echo "Error: kubectl cannot connect to cluster." >&2
  exit 1
fi

pushd tests

# Loop over all directories in the tests directory
ALL_PASSED=true
for d in apps/*/ ; do
    # Run the test
    # Remove apps/ prefix with sed
    d=$(echo $d | sed 's/apps//g' | sed 's/\///g')
    echo "Running test $d"
    ./test-app-discovery.sh $d
    if [ $? -eq 0 ]; then
        echo "Test $d passed"
    else
        echo "Test $d failed"
        ALL_PASSED=false
    fi
done

popd

if [ "$ALL_PASSED" = true ]; then
    echo "All tests passed"
    exit 0
else
    echo "Some tests failed"
    exit 1
fi