package bench

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// startSQLBenchmarkManager registers shutdown before startup can fail. Stop
// joins workers before the earlier chain mock and container cleanup run.
func startSQLBenchmarkManager(tb testing.TB,
	config wallet.ManagerConfig) (*wallet.Manager, []*wallet.Wallet) {

	tb.Helper()

	manager, err := wallet.NewManager(tb.Context(), config)
	require.NoError(tb, err)
	tb.Cleanup(func() { require.NoError(tb, manager.Stop()) })
	wallets, err := manager.Start(tb.Context())
	require.NoError(tb, err)

	return manager, wallets
}

// seedSQLBenchmarkWallet uses normal Manager account/key allocation followed by
// Store history writes. The standalone seeding Store has no key deriver.
func seedSQLBenchmarkWallet(tb testing.TB, manager *wallet.Manager,
	store db.Store, workload bwtest.NodeBenchmarkWorkload) {

	tb.Helper()

	phaseStarted := time.Now()
	params := wallet.CreateWalletParams{
		Name:              "list-unspent-benchmark",
		Mode:              wallet.ModeImportSeed,
		Seed:              workload.Seed,
		Birthday:          workload.Birthday,
		PrivatePassphrase: []byte("private"),
	}
	w, err := manager.Create(params)
	require.NoError(tb, err)
	require.NoError(tb, w.Unlock(tb.Context(), wallet.UnlockRequest{
		Passphrase: []byte("private"),
		Timeout:    -1,
	}))

	// Match ordinary defaults and lnd's precreated internal key accounts;
	// exact SQL account creation supports chain-excluded key families.
	for _, scope := range waddrmgr.DefaultKeyScopes {
		number := wallet.AccountNumber(0)
		params := wallet.NewAccountParams{
			Scope:         scope,
			Name:          "default",
			AccountNumber: &number,
		}
		_, err := w.NewAccount(tb.Context(), params)
		require.NoError(tb, err)
	}

	keyScope := bwtest.NodeBenchmarkChannelScope()
	schema := waddrmgr.ScopeAddrMap[waddrmgr.KeyScopeBIP0084]

	families := workload.NumAccounts - uint32(len(waddrmgr.DefaultKeyScopes))
	for account := range families {
		number := wallet.AccountNumber(account)

		name := "default"
		if account != 0 {
			name = fmt.Sprintf("act:%d", account)
		}

		params := wallet.NewAccountParams{
			Scope:         keyScope,
			Name:          name,
			AccountNumber: &number,
			AddrSchema:    &schema,
			NoChainSync:   true,
		}
		_, err := w.NewAccount(tb.Context(), params)
		require.NoError(tb, err)
	}

	tb.Logf("fixture accounts: %s", time.Since(phaseStarted))
	phaseStarted = time.Now()

	// Bulk allocation registers ordinary chain-synced address batches. The
	// public key allocator derives internal NoChainSync keys, so neither
	// path needs a benchmark-only cryptographic callback.
	var scripts [][]byte
	for _, batch := range workload.AddressBatches() {
		selector := wallet.NewAccountSelectorByNumber(
			batch.Scope, wallet.AccountNumber(batch.Account),
		)
		if batch.Scope == keyScope {
			for range batch.Count {
				_, err := w.AllocateNextKey(tb.Context(), selector, false)
				require.NoError(tb, err)
			}

			// Channel keys fill internal families, not payment addresses.
			// Keep them out of Batch's receiving/change/closing script order.
			continue
		}

		for remaining := batch.Count; remaining > 0; {
			count := min(remaining, wallet.MaxBulkAddressCount)
			addresses, err := w.NewBulkAddresses(
				tb.Context(), selector, batch.Internal, count,
			)
			require.NoError(tb, err)

			for _, addr := range addresses {
				script, err := txscript.PayToAddrScript(addr.Addr)
				require.NoError(tb, err)

				scripts = append(scripts, script)
			}

			remaining -= count
		}
	}

	tb.Logf("fixture allocation: %s", time.Since(phaseStarted))
	phaseStarted = time.Now()

	// SQL can persist the complete normalized graph and final tip through
	// its existing batch transaction; no legacy sync-tip progression is
	// needed.
	require.NoError(tb, store.ApplyTxBatch(
		tb.Context(), workload.Batch(w.ID(), scripts),
	))
	tb.Logf("fixture history: %s", time.Since(phaseStarted))

	// Validate committed data before a newly prepared snapshot can be saved.
	bwtest.AssertNodeBenchmarkWallet(tb, store, w.ID(), workload)
}

// SQLBenchmarkTarget selects a retained cooperative return outside measurement.
// Canonical txid/index order makes all point reads choose the same transaction
// shape regardless of backend enumeration order. No fixture totals are checked.
func SQLBenchmarkTarget(tb testing.TB, w *wallet.Wallet) *wallet.Utxo {
	tb.Helper()

	utxos, err := w.ListUnspent(tb.Context(), wallet.UtxoQuery{
		MaxConfs: math.MaxInt32,
	})
	require.NoError(tb, err)

	// Native fields feed the shared rule without adapting the Wallet result.
	target, found := bwtest.SelectNodeBenchmarkTarget(
		utxos, func(utxo *wallet.Utxo) (btcutil.Amount, string, uint32) {
			return utxo.Amount, utxo.OutPoint.Hash.String(),
				utxo.OutPoint.Index
		},
	)
	if !found {
		tb.Fatal("prepare point read: no cooperative return")
	}

	return target
}
