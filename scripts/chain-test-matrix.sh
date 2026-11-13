#!/bin/bash

# chain-test-matrix.sh resolves the release-check suite's Core window and checksums.
# Callers supply both btcd pins; publish one complete matrix through GITHUB_OUTPUT
# so all downstream lanes use the same upstream evidence for this run.
set -euo pipefail

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
        jq -sc --arg latest "$1" --arg previous "$2" \
            '{include: (. + [
                {chain: "btcd", version: $latest},
                {chain: "btcd", version: $previous}
            ])}'
)

# Log the exact per-run pins, then pass the same complete JSON to the next job.
printf '%s\n' "$matrix"
printf 'matrix=%s\n' "$matrix" >> "$GITHUB_OUTPUT"
