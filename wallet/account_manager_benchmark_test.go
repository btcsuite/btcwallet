package wallet

import (
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// BenchmarkAccountsAPI compares ListAccountsByScope and deprecated Accounts
// APIs using identical test data across multiple dataset sizes. Test names
// start with dataset size to group API comparisons for benchstat analysis.
func BenchmarkAccountsAPI(b *testing.B) {
	benchmarkSizes := generateBenchmarkSizes()

	for _, size := range benchmarkSizes {
		b.Run(size.name()+"/ListAccountsByScope", func(b *testing.B) {
			w, cleanup := setupBenchmarkWallet(
				b, size.numAccounts, size.numUTXOs,
			)
			b.Cleanup(cleanup)

			scope := waddrmgr.KeyScopeBIP0044
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_, err := w.ListAccountsByScope(
					b.Context(), scope,
				)
				require.NoError(b, err)
			}
		})

		b.Run(size.name()+"/AccountsDeprecated", func(b *testing.B) {
			w, cleanup := setupBenchmarkWallet(
				b, size.numAccounts, size.numUTXOs,
			)
			b.Cleanup(cleanup)

			scope := waddrmgr.KeyScopeBIP0044
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_, err := w.Accounts(scope)
				require.NoError(b, err)
			}
		})
	}
}

// setupBenchmarkWallet creates a wallet with test data for benchmarking. It
// also returns a cleanup function to remove the wallet database.
func setupBenchmarkWallet(b *testing.B, numAccounts,
	numUTXOs int) (*Wallet, func()) {

	b.Helper()

	// Since testWallet requires a *testing.T, we can't pass the benchmark's
	// *testing.B. Instead, we create a dummy *testing.T and manually fail
	// the benchmark if the setup fails.
	t := &testing.T{}
	w, cleanup := testWallet(t)
	require.False(b, t.Failed(), "testWallet setup failed")

	addresses := createTestAccounts(b, w, numAccounts)
	createTestUTXOs(b, w, addresses, numUTXOs)

	return w, cleanup
}

// createTestAccounts creates the specified number of test accounts and
// returns all the external addresses generated for those accounts.
func createTestAccounts(b *testing.B, w *Wallet,
	numAccounts int) []waddrmgr.ManagedAddress {

	b.Helper()

	var allAddresses []waddrmgr.ManagedAddress

	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		return createAccountsInScope(w, tx, numAccounts, &allAddresses)
	})

	require.NoError(b, err, "failed to create test accounts: %v", err)

	return allAddresses
}

// createAccountsInScope creates accounts within a specific scope.
func createAccountsInScope(w *Wallet, tx walletdb.ReadWriteTx,
	numAccounts int, allAddresses *[]waddrmgr.ManagedAddress) error {

	scope := waddrmgr.KeyScopeBIP0044
	manager, err := w.addrStore.FetchScopedKeyManager(scope)
	if err != nil {
		return err
	}

	addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

	for i := range numAccounts {
		name := fmt.Sprintf("bench-account-%d", i)
		account, err := manager.NewAccount(addrmgrNs, name)
		if err != nil {
			return err
		}

		addrs, err := manager.NextExternalAddresses(
			addrmgrNs, account, 5,
		)
		if err != nil {
			return err
		}

		*allAddresses = append(*allAddresses, addrs...)
	}
	return nil
}

// createTestUTXOs creates the specified number of test UTXOs using the provided
// addresses for benchmark data setup.
func createTestUTXOs(b *testing.B, w *Wallet,
	addresses []waddrmgr.ManagedAddress, numUTXOs int) {

	b.Helper()

	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		msgTx := TstTx.MsgTx()

		for i := 0; i < numUTXOs && i < len(addresses); i++ {
			newMsgTx := wire.NewMsgTx(msgTx.Version)
			addr := addresses[i%len(addresses)]

			pkScript, err := txscript.PayToAddrScript(
				addr.Address(),
			)
			if err != nil {
				return err
			}

			// Add a dummy tx output to make it valid.
			amount := btcutil.Amount(100000 + i*1000)
			txOut := wire.NewTxOut(int64(amount), pkScript)
			newMsgTx.AddTxOut(txOut)

			// Add a dummy tx input to make it valid.
			prevHash := chainhash.Hash{}
			prevHash[0] = byte(i)
			txIn := wire.NewTxIn(
				wire.NewOutPoint(&prevHash, 0), nil, nil,
			)
			newMsgTx.AddTxIn(txIn)

			rec, err := wtxmgr.NewTxRecordFromMsgTx(
				newMsgTx, time.Now(),
			)
			if err != nil {
				return err
			}

			blockMeta := &wtxmgr.BlockMeta{
				Block: wtxmgr.Block{
					Hash:   chainhash.Hash{},
					Height: 1,
				},
				Time: time.Now(),
			}

			err = w.txStore.InsertTx(txmgrNs, rec, blockMeta)
			if err != nil {
				return err
			}

			// Mark the output as unspent.
			if err = w.txStore.AddCredit(
				txmgrNs, rec, blockMeta, 0, false,
			); err != nil {
				return err
			}
		}

		return nil
	})

	require.NoError(b, err, "failed to create test UTXOs: %v", err)
}

// benchmarkDataSize represents different test data sizes for stress testing.
type benchmarkDataSize struct {
	numAccounts int
	numUTXOs    int
}

// name returns a dynamically generated benchmark name based on accounts and
// UTXOs with leading zeros for proper sorting in visualization tools.
func (b benchmarkDataSize) name() string {
	// Intentionally using leading zeros for proper sorting.
	return fmt.Sprintf("%02d-Accounts-%05d-UTXOs", b.numAccounts,
		b.numUTXOs)
}

// generateBenchmarkSizes creates benchmark data sizes programmatically.
func generateBenchmarkSizes() []benchmarkDataSize {
	var sizes []benchmarkDataSize

	// Generate UTXO sizes from 2^0 to 2^14 and account sizes from 5 to 75.
	for i := 0; i <= 14; i++ {
		numUTXOs := 1 << i
		numAccounts := 5 + (i * 5)
		sizes = append(sizes, benchmarkDataSize{
			numAccounts: numAccounts,
			numUTXOs:    numUTXOs,
		})
	}

	return sizes
}
