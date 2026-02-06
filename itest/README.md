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

# Select a wallet database backend.
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
