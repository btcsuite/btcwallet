#!/bin/bash

# Find all directories containing go.mod files, starting from depth 2
SUBMODULES=$(find . -mindepth 2 -name "go.mod" -exec dirname {} \;)

# Run 'go mod tidy' for the root project
go mod tidy

# Run 'go mod tidy' for each submodule
for submodule in $SUBMODULES
do
  # Navigate to the submodule directory
  pushd "$submodule" || exit

  # Run 'go mod tidy' in the submodule
  go mod tidy

  # Return to the previous directory
  popd || exit
done
