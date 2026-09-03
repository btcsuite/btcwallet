#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -lt "1" || "$#" -gt "3" ]]; then
    echo "usage: $0 <lnd-checkout> [btcwallet-ref] [lnd-ref]" >&2
    exit 2
fi

root="$(git rev-parse --show-toplevel)"
lnd="$(cd "$1" && pwd)"
default_btcwallet_ref="$(awk -F, '{gsub(/"/, "", $2); if ($2 == "master") {gsub(/"/, "", $6); print $6}}' \
    "${root}/docs/developer/sql_port_inventory/source_refs.csv")"
default_lnd_ref="31168557c3a8602d7669c1eb86eddd07d9892bc6"
btcwallet_ref="${2:-${default_btcwallet_ref}}"
lnd_ref="${3:-${default_lnd_ref}}"
out="${root}/docs/developer/sql_port_inventory/api_baseline.md"
tmp_root="$(mktemp -d)"
tmp_btcwallet="${tmp_root}/btcwallet"
tmp_lnd="${tmp_root}/lnd"

cleanup() {
	git -C "${root}" worktree remove --force "${tmp_btcwallet}" \
		>/dev/null 2>&1 || true
	git -C "${lnd}" worktree remove --force "${tmp_lnd}" \
		>/dev/null 2>&1 || true
	rm -rf "${tmp_root}"
}
trap cleanup EXIT

git -C "${root}" worktree add --detach "${tmp_btcwallet}" \
    "${btcwallet_ref}" >/dev/null
git -C "${lnd}" worktree add --detach "${tmp_lnd}" "${lnd_ref}" \
    >/dev/null

btcwallet_sha="$(git -C "${tmp_btcwallet}" rev-parse HEAD)"
lnd_sha="$(git -C "${tmp_lnd}" rev-parse HEAD)"
test "${btcwallet_sha}" = "$(git -C "${root}" rev-parse "${btcwallet_ref}^{commit}")"
test "${lnd_sha}" = "$(git -C "${lnd}" rev-parse "${lnd_ref}^{commit}")"

# The generator uses go/packages from lnd's own tool dependency set. Running
# it from a clean lnd worktree avoids adding an audit-only dependency to
# btcwallet or including local lnd edits in the baseline.
(
    cd "${tmp_lnd}"
    go run "${root}/scripts/sql-port-api-baseline.go" \
        -btcwallet "${tmp_btcwallet}" -lnd "${tmp_lnd}" -out "${out}"
)

test -s "${out}"
rg -q '^# SQL Port API Baseline$' "${out}"
rg -q '^## `wallet.Interface`$' "${out}"

echo "wrote ${out}"
