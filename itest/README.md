# itest

`itest` contains end-to-end integration tests for `btcwallet` using the harness
in `bwtest`.

## Running Tests

Common invocations:

```bash
make itest

# Select a chain backend.
make itest chain=btcd
make itest chain=bitcoind

# Select a wallet database backend. Default: sqlite.
make itest db=sqlite
make itest db=kvdb

# Filter cases by regex.
make itest icase=manager
```

The `chain` and `db` variables are forwarded into the test binary as flags.

## Test Case Naming

Integration test case names must follow:

```
component action
```

For example:

```
manager create wallet
```

This is validated by `itest/main_test.go`.

## Logs

Each test run creates a per-run log directory under:

`itest/test-logs/log-<chain>-<db>-YYYYMMDD-HHMMSS/`

The harness flattens backend logs into:

- `miner.log`
- `chain_backend.log`

Wallet logs are created per test case:

- `wallet-<testname>.log`

The log directory path is printed when it is created.

## Release Compatibility Checks

After this workflow is present on `sql-wallet`, cut a release branch such as
`v0.19-branch` from the maintained commit and push the version bump there. Every
push to `v0.*-branch`, including later fixes without a version change, starts
**Release checks** automatically. Ordinary pull requests keep normal CI.

A release run calls the full normal CI workflow at the same candidate commit:
static/generated checks, lint, unit/race tests, database integration tests and
current-version chain integration tests. The commit-range check stays PR-only
because it needs a pull-request base. Release compatibility runs in addition
to this full suite, and both must pass before tagging.

The discovery job selects the latest stable patch of the three newest Bitcoin
Core major lines and reads their official archive checksums. The next job runs
the complete SQLite suite for each Core release and the two selected btcd
releases. The support window rolls forward rather than growing. Core uses the
latest selected btcd as its miner; Neutrino stays in normal CI.

After the complete release run passes, create and push the maintainer-signed
release tag at the exact commit SHA shown in that successful run. If the
candidate changes, wait for the new push's checks before tagging it. These
checks do not create tags, build release artifacts or publish releases.

Use Actions' rerun operation to retry the same tested commit. Manual dispatch
for a selected ref is also available once `release.yml` exists on the default
branch, `master`. Automatic release-branch pushes only require the workflow
on that branch; they do not depend on manual-dispatch registration on master.
