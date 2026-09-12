#!/bin/bash

# Keep unset-variable and pipeline safety, but do NOT use `set -e` here.
#
# We want two properties at the same time:
# 1. `go mod tidy` should run for the root module and every nested module, so we
#    still auto-fix any module that *can* be tidied in the current run.
# 2. A failure in one module must still make the overall script fail so CI does
#    not silently pass over a broken submodule.
#
# Using `set -e` would stop on the first failing module and skip the remaining
# tidies. Instead, we run each module explicitly, collect failures, and exit
# non-zero at the end if any module failed.
set -uo pipefail

# Collect module directories whose `go mod tidy` invocation failed.
failures=()

run_tidy() {
  local module_dir="$1"

  # Run each tidy in the target module directory so the command behaves as if a
  # developer had entered that module and run `go mod tidy` manually.
  echo "Running 'go mod tidy' in ${module_dir}"

  if ! (
    # Turn off any parent go.work file. We want to validate each module as an
    # independent module, because CI and release consumers will resolve module
    # dependencies that way.
    cd "$module_dir"
    GOWORK=off go mod tidy
  ); then
    # Keep going so other modules still get tidied, but remember the failure so
    # the script can fail loudly once every module has been attempted.
    failures+=("$module_dir")
  fi
}

# Tidy the repository root module first.
run_tidy "."

# Tidy every actual nested Go module.
#
# We intentionally discover module directories from real `go.mod` paths instead
# of truncating the path (for example, `wallet/txauthor`, `wallet/txrules`, and
# `wallet/txsizes` are distinct modules and must be tidied separately).
while IFS= read -r submodule; do
  run_tidy "$submodule"
done < <(find . -mindepth 2 -name "go.mod" -exec dirname {} \; | sort -u)

# Fail at the end if any module failed to tidy. This preserves the previous
# “tidy as much as possible” behavior while making module errors visible to CI.
if [ ${#failures[@]} -ne 0 ]; then
  echo
  echo "go mod tidy failed for the following modules:"
  printf '  - %s\n' "${failures[@]}"
  exit 1
fi
