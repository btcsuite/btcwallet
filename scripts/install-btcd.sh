#!/bin/bash

# install-btcd.sh authenticates an exact tagged module and verifies its daemon.
# Scope compiler selection to installation so the caller's wallet toolchain
# stays unchanged when the selected daemon needs a newer Go release.
set -euo pipefail

btcd_version=$1
GOTOOLCHAIN=auto go install -v github.com/btcsuite/btcd@"$btcd_version"

# Check the PATH binary that the harness will run for the backend or miner.
version=$(btcd --version)
echo "$version"
expected=${btcd_version#v}

# The published stable v0.26.2 tag retains this exact beta report suffix.
if [ "$btcd_version" = v0.26.2 ]; then
    expected="$expected-beta"
fi

test "$version" = "btcd version $expected"
