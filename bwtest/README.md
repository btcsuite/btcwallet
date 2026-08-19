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

## Signed Transactions

`(*HarnessTest).SignSpend` authors and signs a transaction from a wallet's own
coins. It takes a `SpendFixture` naming the inputs and the outputs, and returns
the signed transaction:

```go
tx := t.SignSpend(w, bwtest.SpendFixture{
	Inputs:  []wire.OutPoint{funding.WalletOutpoints[0]},
	Outputs: []wire.TxOut{{Value: amount, PkScript: pkScript}},
})
```

The inputs and outputs are used verbatim, in the order given, and every input is
final. Unlike `CreateTransaction` no coin selection, change or output policy is
applied, so a case can author a transaction the network is required to reject —
a dust payment, a fee the relay will not carry — which is what publication tests
need. Cases that mean to test coin selection or change should use
`CreateTransaction` instead.

The wallet must be started, synced and unlocked, and it must own every named
input.

To build a rejected output without writing down an amount that drifts from
policy, `(*HarnessTest).DustThreshold` returns the smallest amount an output
paying a given script may carry; anything below it is dust.

## Chain Backend Capabilities

Not every backend answers every question. `ChainBackend.SupportsMempoolAcceptance`
reports whether the backend under test runs the mempool acceptance check, and
each backend answers for the client it constructs so the answer cannot drift
from the implementation. Neutrino is a light client with no mempool and reports
the check as unimplemented instead of returning a verdict, so cases reach it as
`t.Backend.SupportsMempoolAcceptance()` and assert a definite result on both
sides of the split rather than skipping a backend.

## Fast Scrypt

`bwtest` sets `waddrmgr.DefaultScryptOptions` to `waddrmgr.FastScryptOptions` via
an `init()` function. Any package that imports `bwtest` (including `itest`)
automatically benefits from faster key derivation, avoiding CPU exhaustion and
timeouts — especially when running with `-race`.
