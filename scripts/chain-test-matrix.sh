#!/bin/bash

# chain-test-matrix.sh resolves the release-check suite's Core window and checksums.
# The caller supplies the previous btcd release; main.yml owns the current pin.
# Publish one complete matrix so downstream lanes share this run's evidence.
set -euo pipefail

# Reuse ordinary CI's canonical pin for the current release row and Core miner.
btcd_version=$(yq -er '.env.BTCD_VERSION_LATEST' .github/workflows/main.yml)

# Paginate the official releases, excluding drafts/RCs. Compare numeric parts
# rather than publish order so older-line patches cannot displace newer majors.
versions=$(
    gh api --paginate --slurp 'repos/bitcoin/bitcoin/releases?per_page=100' |
        jq -er '
            [.[][] | select(.draft == false and .prerelease == false)
                | .tag_name
                | select(test("^v[0-9]+\\.[0-9]+(\\.[0-9]+)?$"))
                | ltrimstr("v")]
            | group_by(split(".")[0] | tonumber)
            | map(max_by(split(".") | map(tonumber)))
            | sort_by(split(".")[0] | tonumber) | reverse | .[:3]
            | if length == 3 then .[]
              else error("need three stable Core major lines") end
        '
)

# Bind each release to its exact official Linux archive. Missing evidence fails
# the pipeline before an output can silently shrink the requested test window.
# Explicit exits also propagate failures inside Bash command substitutions.
matrix=$(
    while IFS= read -r version; do
        archive="bitcoin-${version}-x86_64-linux-gnu.tar.gz"
        checksum=$(
            curl --fail --location --retry 3 \
                "https://bitcoincore.org/bin/bitcoin-core-${version}/SHA256SUMS" |
                awk -v archive="$archive" '$2 == archive { print $1 }'
        ) || exit 1
        [[ $checksum =~ ^[[:xdigit:]]{64}$ ]] || exit 1
        jq -nc --arg version "$version" --arg sha256 "$checksum" \
            '{chain: "bitcoind", version: $version, sha256: $sha256}' || exit 1
    done <<< "$versions" |
        jq -sc --arg latest "$btcd_version" --arg previous "$1" \
            '{include: (. + [
                {chain: "btcd", version: $latest},
                {chain: "btcd", version: $previous}
            ])}'
)

# Publish the matrix and miner pin together only after discovery succeeds,
# so dependent suites cannot consume a partial compatibility window.
printf '%s\n' "$matrix"
printf 'matrix=%s\nbtcd_version=%s\n' "$matrix" "$btcd_version" \
    >> "$GITHUB_OUTPUT"
