# bwtest

`bwtest` contains the integration test harness used by `itest`.

## Overview

The harness provides:

- A shared miner (btcd) that produces blocks for all test cases.
- A configurable chain backend under test (`btcd`, `bitcoind`, `neutrino`).
- Per-subtest resources:
  - A fresh `chain.Interface` instance.
  - A fresh wallet database instance.
- Cleanup that keeps tests isolated:
  - Stops wallets created by the test.
  - Requires the miner mempool to be empty on success.

## Logs

Each test run creates a per-run log directory under `itest/test-logs`.

- Backend logs are flattened into `miner.log` and `chain_backend.log`.
- Wallet logs are written per test case as `wallet-<testname>.log`.

## Backends

Chain backends are implemented in separate files:

- `bwtest/btcd.go`
- `bwtest/bitcoind.go`
- `bwtest/neutrino.go`

The `bitcoind` backend uses ZMQ for block/tx notifications.

## Wallet Helpers

`bwtest` includes convenience helpers for tests that do not want to directly
exercise the wallet manager:

- `(*HarnessTest).CreateEmptyWallet`
- `(*HarnessTest).CreateFundedWallet`

Example usage:

```go
func testFoo(t *bwtest.HarnessTest) {
	t.CreateEmptyWallet()

	// Now add tests that need a started wallet instance.
}

func testBar(t *bwtest.HarnessTest) {
	t.CreateFundedWallet()

	// Now add tests that need a wallet with spendable funds.
}
```

Manager-focused tests should continue to create wallets through the manager API
directly.

## Fast Scrypt

`bwtest` sets `waddrmgr.DefaultScryptOptions` to `waddrmgr.FastScryptOptions` via
an `init()` function. Any package that imports `bwtest` (including `itest`)
automatically benefits from faster key derivation, avoiding CPU exhaustion and
timeouts — especially when running with `-race`.
