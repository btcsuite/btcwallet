#!/bin/bash

set -euo pipefail

# Run 'go mod tidy' for root.
go mod tidy

# Run 'go mod tidy' for each module.
while IFS= read -r -d '' module_file; do
  module_dir=$(dirname "$module_file")
  echo "Running 'go mod tidy' in $module_dir"
  (
    cd "$module_dir"
    go mod tidy
  )
done < <(find . -mindepth 2 -name "go.mod" -print0)
