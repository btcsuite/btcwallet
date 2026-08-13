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

`bwtest` owns wallet creation, funding and lock policy so component tests do
not each define their own. `(*HarnessTest).NewWallet` is the single
parameterized entry point; it takes a `WalletFixture` describing what the case
needs and returns the wallet with the outpoints funding produced:

```go
func testFoo(t *bwtest.HarnessTest) {
	w, outpoints := t.NewWallet(bwtest.WalletFixture{
		AddrType: waddrmgr.WitnessPubKey,
		Amounts:  []btcutil.Amount{oneBTC, twoBTC},
		Unlocked: true,
	})

	// Now add tests that need a wallet with two spendable coins.
}
```

`WalletFixture` carries the funding address type, the funding amounts, whether
to unlock, and whether to leave the wallet unstarted. A case that selects the
funded coins derives its key scope from the same `AddrType` with `KeyScope()`,
so the funded scope has one authority.

Two convenience wrappers remain for cases that need nothing else:

- `(*HarnessTest).CreateEmptyWallet`
- `(*HarnessTest).CreateFundedWallet`

Funding is also available on its own through `(*HarnessTest).FundWallet` and
`(*HarnessTest).FundWalletOfType`, and addresses through
`(*HarnessTest).NewWalletAddress` and `(*HarnessTest).NewWalletAddressOfType`.

Manager-focused tests should continue to create wallets through the manager API
directly.

## Fast Scrypt

`bwtest` sets `waddrmgr.DefaultScryptOptions` to `waddrmgr.FastScryptOptions` via
an `init()` function. Any package that imports `bwtest` (including `itest`)
automatically benefits from faster key derivation, avoiding CPU exhaustion and
timeouts — especially when running with `-race`.
