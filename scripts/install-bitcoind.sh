#!/bin/bash

# install-bitcoind.sh installs a workflow-pinned Linux amd64 Core archive.
# Callers supply the release and SHA-256; verify before extraction or execution
# so both ordinary and release-check jobs use the same authenticated artifact.
set -euo pipefail

core_version=$1
core_sha256=$2
archive="$RUNNER_TEMP/bitcoin-${core_version}-x86_64-linux-gnu.tar.gz"

curl --fail --location --retry 3 \
    "https://bitcoincore.org/bin/bitcoin-core-${core_version}/$(basename "$archive")" \
    --output "$archive"
echo "$core_sha256  $archive" | sha256sum --check
tar -xzf "$archive" -C "$RUNNER_TEMP"
install -m 755 "$RUNNER_TEMP/bitcoin-${core_version}/bin/bitcoind" \
    "$GOBIN/bitcoind"

# Reject a wrong PATH executable; Core 32 appends a daemon name to its report,
# so compare the complete version token rather than the entire first line.
version=$(bitcoind --version | sed -n '1p')
echo "$version"
reported=${version#* version v}
# Two-part tags omit the daemon's final zero; three-part tags are already exact.
expected=$core_version
if [[ $core_version != *.*.* ]]; then
    expected="$core_version.0"
fi
test "${reported%% *}" = "$expected"
