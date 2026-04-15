//go:build itest

package itest

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/pg"
	"github.com/stretchr/testify/require"
)

// dropTableForCorruption removes one backing table so the public store methods
// surface the backend query errors exercised by the corruption tests.
func dropTableForCorruption(t *testing.T, store interface{ DB() *sql.DB },
	table string) {
	t.Helper()

	stmt := fmt.Sprintf("DROP TABLE %s", table)
	if _, ok := any(store).(*pg.Store); ok {
		stmt += " CASCADE"
	}

	_, err := store.DB().ExecContext(t.Context(), stmt)
	require.NoError(t, err)
}

// TestGetAndListTxRejectCorruptedStatus verifies that tx reads fail loudly when
// the stored status escapes the supported enum.
func TestGetAndListTxRejectCorruptedStatus(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-corrupted-tx-status")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	queries := store.Queries()
	confirmedBlock := CreateBlockFixture(t, queries, 265)

	pendingTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 2100, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       pendingTx,
			Received: time.Unix(1710000895, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]btcutil.Address{0: nil},
		},
	)
	require.NoError(t, err)

	confirmedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 3100, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       confirmedTx,
			Received: time.Unix(1710000896, 0),
			Block:    &confirmedBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]btcutil.Address{0: nil},
		},
	)
	require.NoError(t, err)

	corruptTransactionStatus(t, store, walletID, pendingTx.TxHash(), 99)

	_, err = store.GetTx(
		t.Context(),
		db.GetTxQuery{
			WalletID: walletID,
			Txid:     pendingTx.TxHash(),
		},
	)
	require.ErrorContains(t, err, "invalid tx status")

	_, err = store.ListTxns(
		t.Context(),
		db.ListTxnsQuery{
			WalletID:    walletID,
			UnminedOnly: true,
		},
	)
	require.ErrorContains(t, err, "invalid tx status")

	corruptTransactionStatus(t, store, walletID, confirmedTx.TxHash(), 99)

	_, err = store.ListTxns(
		t.Context(),
		db.ListTxnsQuery{
			WalletID:    walletID,
			StartHeight: confirmedBlock.Height,
			EndHeight:   confirmedBlock.Height,
		},
	)
	require.ErrorContains(t, err, "invalid tx status")
}

// TestDeleteTxRejectsCorruptedStatus verifies that DeleteTx rejects stored rows
// with an invalid wallet-visible status code.
func TestDeleteTxRejectsCorruptedStatus(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-corrupted-status")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 2300, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000897, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]btcutil.Address{0: nil},
		},
	)
	require.NoError(t, err)

	corruptTransactionStatus(t, store, walletID, tx.TxHash(), 99)

	err = store.DeleteTx(
		t.Context(),
		db.DeleteTxParams{
			WalletID: walletID,
			Txid:     tx.TxHash(),
		},
	)
	require.ErrorContains(t, err, "invalid tx status")
}

// TestCreateTxRejectsCorruptedExistingStatus verifies that CreateTx surfaces an
// invalid stored status while checking whether the tx hash already exists.
func TestCreateTxRejectsCorruptedExistingStatus(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-create-corrupted-existing-status")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 2350, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000898, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]btcutil.Address{0: nil},
		},
	)
	require.NoError(t, err)

	corruptTransactionStatus(t, store, walletID, tx.TxHash(), 99)

	err = store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000899, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]btcutil.Address{0: nil},
		},
	)
	require.ErrorContains(t, err, "invalid tx status")
}

// TestInvalidateUnminedTxRejectsCorruptedStatus verifies that invalidation
// rejects a stored root whose wallet-visible status is corrupted.
func TestInvalidateUnminedTxRejectsCorruptedStatus(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-invalidate-corrupted-status")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 2400, PkScript: []byte{0x51}}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000901, 0),
			Status:   db.TxStatusPending,
		},
	)
	require.NoError(t, err)

	corruptTransactionStatus(t, store, walletID, tx.TxHash(), 99)

	err = store.InvalidateUnminedTx(
		t.Context(),
		db.InvalidateUnminedTxParams{
			WalletID: walletID,
			Txid:     tx.TxHash(),
		},
	)
	require.ErrorContains(t, err, "invalid tx status")
}

// TestListTxnsRejectsCorruptedUnminedHash verifies that unmined transaction
// listings fail when a stored transaction hash cannot be decoded.
func TestListTxnsRejectsCorruptedUnminedHash(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-corrupted-unmined-hash")

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 2700, PkScript: []byte{0x51}}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710001400, 0),
			Status:   db.TxStatusPending,
		},
	)
	require.NoError(t, err)

	corruptTransactionHash(t, store, walletID, tx.TxHash(), []byte{1, 2, 3})

	_, err = store.ListTxns(
		t.Context(),
		db.ListTxnsQuery{
			WalletID:    walletID,
			UnminedOnly: true,
		},
	)
	require.ErrorContains(t, err, "tx hash")
}

// TestGetTxRejectsCorruptedConfirmedBlockHeight verifies that confirmed reads
// fail when the joined block height cannot map back into the public block model.
func TestGetTxRejectsCorruptedConfirmedBlockHeight(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-corrupted-confirmed-height")
	queries := store.Queries()
	confirmedBlock := CreateBlockFixture(t, queries, 280)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 2800, PkScript: []byte{0x51}}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710001410, 0),
			Block:    &confirmedBlock,
			Status:   db.TxStatusPublished,
		},
	)
	require.NoError(t, err)

	corruptTransactionBlockHeight(t, store, walletID, tx.TxHash(), -1)

	_, err = store.GetTx(
		t.Context(),
		db.GetTxQuery{
			WalletID: walletID,
			Txid:     tx.TxHash(),
		},
	)
	require.ErrorContains(t, err, "block height")
}

// TestDeleteTxRejectsCorruptedLiveChild verifies that DeleteTx surfaces child
// decode failures while checking the live leaf invariant.
func TestDeleteTxRejectsCorruptedLiveChild(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-corrupted-child")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)

	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       parentTx,
			Received: time.Unix(1710001015, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]btcutil.Address{0: nil},
		},
	)
	require.NoError(t, err)

	childTx := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 4000, PkScript: []byte{0x51}}},
	)
	err = store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       childTx,
			Received: time.Unix(1710001020, 0),
			Status:   db.TxStatusPending,
		},
	)
	require.NoError(t, err)

	corruptTransactionHash(t, store, walletID, childTx.TxHash(), []byte{1, 2, 3})

	err = store.DeleteTx(
		t.Context(),
		db.DeleteTxParams{
			WalletID: walletID,
			Txid:     parentTx.TxHash(),
		},
	)
	require.ErrorContains(t, err, "tx hash")
}

// TestRollbackToBlockRejectsCorruptedCoinbaseRootHash verifies that rollback
// fails loudly when a disconnected coinbase root carries an invalid stored hash.
func TestRollbackToBlockRejectsCorruptedCoinbaseRootHash(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-rollback-corrupted-coinbase-hash")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	queries := store.Queries()
	coinbaseBlock := CreateBlockFixture(t, queries, 290)
	coinbaseTx := newCoinbaseTx(addr.ScriptPubKey)

	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       coinbaseTx,
			Received: time.Unix(1710001420, 0),
			Block:    &coinbaseBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]btcutil.Address{0: nil},
		},
	)
	require.NoError(t, err)

	corruptTransactionHash(t, store, walletID, coinbaseTx.TxHash(), []byte{1, 2, 3})

	err = store.RollbackToBlock(t.Context(), coinbaseBlock.Height)
	require.ErrorContains(t, err, "rollback coinbase hash")
}

// TestCreateTxReturnsQueryErrorWhenTransactionsTableMissing verifies that the
// backend loadExisting path surfaces query errors from the transactions table.
func TestCreateTxReturnsQueryErrorWhenTransactionsTableMissing(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-create-missing-transactions-table")

	dropTableForCorruption(t, store, "transactions")

	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       newRegularTx([]wire.OutPoint{randomOutPoint()}, []*wire.TxOut{{Value: 5500, PkScript: []byte{0x51}}}),
			Received: time.Unix(1710001433, 0),
			Status:   db.TxStatusPending,
		},
	)
	require.ErrorContains(t, err, "get tx metadata")
}

// TestCreateTxReturnsQueryErrorWhenUtxosTableMissing verifies that conflict
// discovery surfaces backend query errors from the UTXO table.
func TestCreateTxReturnsQueryErrorWhenUtxosTableMissing(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-create-missing-utxos-table")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5600, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       parentTx,
			Received: time.Unix(1710001434, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]btcutil.Address{0: nil},
		},
	)
	require.NoError(t, err)

	conflictRoot := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 5500, PkScript: []byte{0x51}}},
	)
	err = store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       conflictRoot,
			Received: time.Unix(1710001435, 0),
			Status:   db.TxStatusPending,
		},
	)
	require.NoError(t, err)

	confirmedBlock := CreateBlockFixture(t, store.Queries(), 292)
	dropTableForCorruption(t, store, "utxos")

	err = store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx: newRegularTx(
				[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 0}},
				[]*wire.TxOut{{Value: 5400, PkScript: []byte{0x52}}},
			),
			Received: time.Unix(1710001436, 0),
			Block:    &confirmedBlock,
			Status:   db.TxStatusPublished,
		},
	)
	require.ErrorContains(t, err, "lookup input conflict")
}

// TestRollbackToBlockReturnsQueryErrorWhenBlocksTableMissing verifies that the
// backend rollback queries surface database errors when the block table is gone.
func TestRollbackToBlockReturnsQueryErrorWhenBlocksTableMissing(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	dropTableForCorruption(t, store, "blocks")

	err := store.RollbackToBlock(t.Context(), 1)
	require.Error(t, err)

	// SQLite still fails while rewinding wallet sync-state heights because
	// wallet_sync_states keeps direct block references with ON DELETE RESTRICT.
	// PostgreSQL drops those dependent rows with CASCADE when the blocks table is
	// removed, so rollback gets far enough to fail on the block delete instead.
	_, ok := any(store).(*pg.Store)
	if ok {
		require.ErrorContains(t, err, "delete blocks at or above height")
		return
	}

	require.ErrorContains(t, err, "rewind wallet sync state heights")
}

// TestLeaseAndReleaseReturnQueryErrorsWhenLeaseTablesMissing verifies that the
// backend lease queries surface direct database errors when the lease table has
// been removed.
func TestLeaseAndReleaseReturnQueryErrorsWhenLeaseTablesMissing(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-missing-utxo-lease-table")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	confirmedBlock := CreateBlockFixture(t, store.Queries(), 293)
	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5700, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710001437, 0),
			Block:    &confirmedBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]btcutil.Address{0: nil},
		},
	)
	require.NoError(t, err)

	outPoint := wire.OutPoint{Hash: tx.TxHash(), Index: 0}
	leaseID := RandomHash()

	dropTableForCorruption(t, store, "utxo_leases")

	_, err = store.LeaseOutput(
		t.Context(),
		db.LeaseOutputParams{
			WalletID: walletID,
			ID:       leaseID,
			OutPoint: outPoint,
			Duration: time.Minute,
		},
	)
	require.ErrorContains(t, err, "acquire lease row")

	err = store.ReleaseOutput(
		t.Context(),
		db.ReleaseOutputParams{
			WalletID: walletID,
			ID:       leaseID,
			OutPoint: outPoint,
		},
	)
	require.ErrorContains(t, err, "release lease row")
}

// TestCreateTxRejectsCorruptedConflictRootHash verifies that confirmed conflict
// reconciliation fails loudly when one conflicting unmined root carries an
// invalid stored hash.
func TestCreateTxRejectsCorruptedConflictRootHash(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-create-corrupted-conflict-hash")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	parentTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5400, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       parentTx,
			Received: time.Unix(1710001430, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]btcutil.Address{0: nil},
		},
	)
	require.NoError(t, err)

	conflictRoot := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 5300, PkScript: []byte{0x51}}},
	)
	err = store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       conflictRoot,
			Received: time.Unix(1710001431, 0),
			Status:   db.TxStatusPending,
		},
	)
	require.NoError(t, err)

	corruptTransactionHash(
		t, store, walletID, conflictRoot.TxHash(), []byte{1, 2, 3},
	)

	confirmedBlock := CreateBlockFixture(t, store.Queries(), 291)
	winnerTx := newRegularTx(
		[]wire.OutPoint{{Hash: parentTx.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 5200, PkScript: []byte{0x52}}},
	)
	err = store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       winnerTx,
			Received: time.Unix(1710001432, 0),
			Block:    &confirmedBlock,
			Status:   db.TxStatusPublished,
		},
	)
	require.ErrorContains(t, err, "tx hash")
}
