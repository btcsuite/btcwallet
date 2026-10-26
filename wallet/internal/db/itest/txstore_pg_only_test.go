//go:build itest && test_db_postgres

package itest

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestCreateTxRejectsBlockHeightOverflowPostgres verifies postgres-specific
// block-height conversion failures surface before insert.
func TestCreateTxRejectsBlockHeightOverflowPostgres(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-create-overflow-height-pg")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 1000, PkScript: []byte{0x51}}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710005000, 0),
			Block: &db.Block{
				Height:    ^uint32(0),
				Hash:      RandomHash(),
				Timestamp: time.Unix(1710005001, 0),
			},
			Status: db.TxStatusPublished,
		},
	)
	require.ErrorContains(t, err, "convert block height")
}

// TestListTxnsRejectHeightOverflowPostgres verifies postgres-specific height
// conversion failures for confirmed transaction listings.
func TestListTxnsRejectHeightOverflowPostgres(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-height-overflow-pg")

	_, err := store.ListTxns(
		t.Context(),
		db.ListTxnsQuery{
			WalletID:    walletID,
			StartHeight: ^uint32(0),
			EndHeight:   0,
		},
	)
	require.ErrorContains(t, err, "convert start height")

	_, err = store.ListTxns(
		t.Context(),
		db.ListTxnsQuery{
			WalletID:    walletID,
			StartHeight: 0,
			EndHeight:   ^uint32(0),
		},
	)
	require.ErrorContains(t, err, "convert end height")
}

// TestRollbackToBlockRejectsHeightOverflowPostgres verifies postgres-specific
// rollback height conversion failures.
func TestRollbackToBlockRejectsHeightOverflowPostgres(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	err := store.RollbackToBlock(t.Context(), ^uint32(0))
	require.ErrorContains(t, err, "convert rollback height")
}

// TestTxGraphChildBeforeRollbackPostgres checks that rollback waits for a
// child write and removes it with its disconnected coinbase parent.
func TestTxGraphChildBeforeRollbackPostgres(t *testing.T) {
	t.Parallel()

	// Arrange: Confirm coinbase A and fund independent input Q. B spends
	// both. Register a second Wallet to exercise rollback's lock order.
	store := NewTestStore(t)
	walletID := newWallet(t, store, "graph")
	newWallet(t, store, "other")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")
	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	funding := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 7000, PkScript: addr.ScriptPubKey}},
	)
	q := wire.OutPoint{Hash: funding.TxHash()}
	root := newCoinbaseTx(addr.ScriptPubKey)
	child := newRegularTx(
		[]wire.OutPoint{{Hash: root.TxHash()}, q},
		[]*wire.TxOut{{Value: 11000, PkScript: addr.ScriptPubKey}},
	)
	block := CreateBlockFixture(t, store.Queries(), 1)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	require.NoError(
		t, store.CreateTx(
			ctx, db.CreateTxParams{
				WalletID: walletID,
				Tx:       funding,
				Received: time.Unix(1, 0),
				Status:   db.TxStatusPending,
				Credits:  map[uint32]address.Address{0: nil},
			},
		),
	)
	require.NoError(
		t, store.CreateTx(
			ctx, db.CreateTxParams{
				WalletID: walletID,
				Tx:       root,
				Received: time.Unix(2, 0),
				Block:    &block,
				Status:   db.TxStatusPublished,
				Credits:  map[uint32]address.Address{0: nil},
			},
		),
	)
	barrier := lockTxGraphOutput(t, ctx, store.DB(), walletID, q)

	// Act: Pause B at Q, then start rollback. Release Q after both calls
	// reach SQL. Cancellation and joining also run if an assertion fails.
	childCall := startTxGraphCall(
		t, cancel, func() error {
			return store.CreateTx(
				ctx, db.CreateTxParams{
					WalletID: walletID,
					Tx:       child,
					Received: time.Unix(3, 0),
					Status:   db.TxStatusPublished,
					Credits:  map[uint32]address.Address{0: nil},
				},
			)
		},
	)
	waitTxGraphCall(t, ctx, store.DB(), childCall, 1)
	rollbackCall := startTxGraphCall(
		t, cancel, func() error {
			return store.RollbackToBlock(ctx, 1)
		},
	)
	waitTxGraphCall(t, ctx, store.DB(), rollbackCall, 2)
	require.NoError(t, barrier.Rollback())
	require.NoError(t, <-childCall)
	require.NoError(t, <-rollbackCall)

	// Assert: Rollback orphans A and fails B. B's credit is gone and its
	// independent input Q is available after both writes finish.
	rootInfo, err := store.GetTx(
		ctx, db.GetTxQuery{
			WalletID: walletID,
			Txid:     root.TxHash(),
		},
	)
	require.NoError(t, err)
	require.Equal(t, db.TxStatusOrphaned, rootInfo.Status)
	childInfo, err := store.GetTx(
		ctx, db.GetTxQuery{
			WalletID: walletID,
			Txid:     child.TxHash(),
		},
	)
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, childInfo.Status)
	_, err = store.GetUtxo(
		ctx, db.GetUtxoQuery{
			WalletID: walletID,
			OutPoint: wire.OutPoint{Hash: child.TxHash()},
		},
	)
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
	_, err = store.GetUtxo(
		ctx, db.GetUtxoQuery{
			WalletID: walletID,
			OutPoint: q,
		},
	)
	require.NoError(t, err)
}

// lockTxGraphOutput holds a UTXO row in a separate SQL transaction. This
// pauses a graph write after its reads, without changing its commit path.
func lockTxGraphOutput(t *testing.T, ctx context.Context, raw *sql.DB,
	walletID uint32, output wire.OutPoint) *sql.Tx {

	t.Helper()

	// Cleanup releases the row even if the test stops before explicit release.
	barrier, err := raw.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = barrier.Rollback() })

	_, err = barrier.ExecContext(
		ctx, `SELECT u.id FROM utxos AS u
		JOIN transactions AS t ON t.id = u.tx_id
		WHERE t.wallet_id = $1 AND t.tx_hash = $2 AND u.output_index = $3
		FOR UPDATE OF u`, walletID, output.Hash[:], output.Index,
	)
	require.NoError(t, err)

	return barrier
}

// startTxGraphCall runs one graph write and joins it during cleanup. Cancel
// releases SQL waits if the test stops before it reads the result.
func startTxGraphCall(t *testing.T, cancel context.CancelFunc,
	call func() error) <-chan error {

	t.Helper()

	// Buffer the result so cleanup can join even if the test stops reading.
	// A separate signal also lets cleanup join after the result is consumed.
	result := make(chan error, 1)

	finished := make(chan struct{})
	go func() {
		defer close(finished)

		result <- call()
	}()

	t.Cleanup(
		func() {
			cancel()
			<-finished
		},
	)

	return result
}

// waitTxGraphCall uses SQL activity to place overlapping writes. Public graph
// results, rather than lock counts, determine whether the test passes.
func waitTxGraphCall(t *testing.T, ctx context.Context, raw *sql.DB,
	result <-chan error, waiting int) {

	t.Helper()

	// The unfixed call can finish instead of waiting. Let it reach the
	// public result checks so the regression fails on graph correctness.
	require.Eventually(
		t, func() bool {
			if len(result) != 0 {
				return true
			}

			var count int

			err := raw.QueryRowContext(
				ctx, `SELECT count(*)
			FROM pg_stat_activity WHERE datname = current_database()
			AND wait_event_type = 'Lock'`,
			).Scan(&count)

			return err == nil && count >= waiting
		}, 10*time.Second, 10*time.Millisecond,
	)
}
