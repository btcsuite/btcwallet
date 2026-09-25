//go:build itest

package itest

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestDeleteUnminedTxRemovesBranch verifies that deleting one unmined root
// erases the root and every descendant, restores the wallet output the root
// spent, and leaves an unrelated unmined spend untouched.
func TestDeleteUnminedTxRemovesBranch(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-unmined-branch")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	block := CreateBlockFixture(t, store.Queries(), 410)

	// The funding tx pays the wallet twice: one output for the branch, one
	// for an unrelated spend that must survive it.
	funding := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{
			{Value: 6000, PkScript: addr.ScriptPubKey},
			{Value: 7000, PkScript: addr.ScriptPubKey},
		},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       funding,
			Received: time.Unix(1710004100, 0),
			Block:    &block,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil, 1: nil},
		},
	)
	require.NoError(t, err)

	rootInput := wire.OutPoint{Hash: funding.TxHash(), Index: 0}
	unrelatedInput := wire.OutPoint{Hash: funding.TxHash(), Index: 1}

	// The root also spends an output the wallet does not own.
	root := newRegularTx(
		[]wire.OutPoint{rootInput, randomOutPoint()},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)
	child := newRegularTx(
		[]wire.OutPoint{{Hash: root.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 4900, PkScript: addr.ScriptPubKey}},
	)
	grandchild := newRegularTx(
		[]wire.OutPoint{{Hash: child.TxHash(), Index: 0}},
		[]*wire.TxOut{{Value: 4800, PkScript: addr.ScriptPubKey}},
	)
	unrelated := newRegularTx(
		[]wire.OutPoint{unrelatedInput},
		[]*wire.TxOut{{Value: 6900, PkScript: []byte{0x52}}},
	)

	// Only outputs paying the wallet address are credited.
	unmined := []struct {
		tx      *wire.MsgTx
		credits map[uint32]address.Address
	}{
		{tx: root, credits: map[uint32]address.Address{0: nil}},
		{tx: child, credits: map[uint32]address.Address{0: nil}},
		{tx: grandchild, credits: map[uint32]address.Address{0: nil}},
		{tx: unrelated},
	}
	for i, entry := range unmined {
		err = store.CreateTx(
			t.Context(),
			db.CreateTxParams{
				WalletID: walletID,
				Tx:       entry.tx,
				Received: time.Unix(int64(1710004110+i), 0),
				Status:   db.TxStatusPublished,
				Credits:  entry.credits,
			},
		)
		require.NoError(t, err)
	}

	// The branch tip is an unspent wallet coin until the branch goes. Both
	// guards would hold without any delete if these went unrecorded.
	branchOutput := wire.OutPoint{Hash: grandchild.TxHash(), Index: 0}
	require.True(t, walletUtxoExists(t, store, walletID, branchOutput))
	require.True(t, walletUtxoSpent(t, store, walletID, rootInput))

	err = store.DeleteUnminedTx(
		t.Context(),
		db.DeleteUnminedTxParams{
			WalletID: walletID,
			Txid:     root.TxHash(),
		},
	)
	require.NoError(t, err)

	// The whole branch is gone, not retained as history.
	for _, tx := range []*wire.MsgTx{root, child, grandchild} {
		_, err = store.GetTx(
			t.Context(),
			db.GetTxQuery{WalletID: walletID, Txid: tx.TxHash()},
		)
		require.ErrorIs(t, err, db.ErrTxNotFound)
	}

	// The outputs the branch created are gone with it. A spent output would
	// read as absent either way, so this checks the unspent tip.
	require.False(t, walletUtxoExists(t, store, walletID, branchOutput))

	// The wallet output the root spent is spendable again.
	require.True(t, walletUtxoExists(t, store, walletID, rootInput))
	require.False(t, walletUtxoSpent(t, store, walletID, rootInput))

	// The unrelated spend keeps both its row and its claim.
	unrelatedInfo, err := store.GetTx(
		t.Context(),
		db.GetTxQuery{WalletID: walletID, Txid: unrelated.TxHash()},
	)
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPublished, unrelatedInfo.Status)
	require.True(t, walletUtxoSpent(t, store, walletID, unrelatedInput))
}

// TestDeleteUnminedTxRejectsConfirmedAndMissing verifies that a confirmed row
// and an unknown hash are refused with stable identities, and that the
// confirmed row is left untouched.
func TestDeleteUnminedTxRejectsConfirmedAndMissing(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-unmined-errors")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	block := CreateBlockFixture(t, store.Queries(), 420)
	confirmed := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 5200, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       confirmed,
			Received: time.Unix(1710004130, 0),
			Block:    &block,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	err = store.DeleteUnminedTx(
		t.Context(),
		db.DeleteUnminedTxParams{
			WalletID: walletID,
			Txid:     confirmed.TxHash(),
		},
	)
	require.ErrorIs(t, err, db.ErrDeleteRequiresUnmined)

	confirmedInfo, err := store.GetTx(
		t.Context(),
		db.GetTxQuery{WalletID: walletID, Txid: confirmed.TxHash()},
	)
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPublished, confirmedInfo.Status)

	err = store.DeleteUnminedTx(
		t.Context(),
		db.DeleteUnminedTxParams{
			WalletID: walletID,
			Txid:     RandomHash(),
		},
	)
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestDeleteUnminedTxRemovesInvalidatedDescendant verifies that a descendant
// already marked failed leaves with its parent, and that both transactions can
// be recorded again if the chain confirms them after all.
func TestDeleteUnminedTxRemovesInvalidatedDescendant(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-unmined-invalidated")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	block := CreateBlockFixture(t, store.Queries(), 450)

	funding := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 9000, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       funding,
			Received: time.Unix(1710004400, 0),
			Block:    &block,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	parent := newRegularTx(
		[]wire.OutPoint{{Hash: funding.TxHash()}},
		[]*wire.TxOut{{Value: 8000, PkScript: addr.ScriptPubKey}},
	)

	child := newRegularTx(
		[]wire.OutPoint{{Hash: parent.TxHash()}},
		[]*wire.TxOut{{Value: 7000, PkScript: addr.ScriptPubKey}},
	)
	for i, tx := range []*wire.MsgTx{parent, child} {
		err = store.CreateTx(
			t.Context(),
			db.CreateTxParams{
				WalletID: walletID,
				Tx:       tx,
				Received: time.Unix(int64(1710004410+i), 0),
				Status:   db.TxStatusPublished,
				Credits:  map[uint32]address.Address{0: nil},
			},
		)
		require.NoError(t, err)
	}

	// The child is invalidated first, so the parent is deleted while a
	// retained failed row still depends on it.
	err = store.InvalidateUnminedTx(
		t.Context(),
		db.InvalidateUnminedTxParams{
			WalletID: walletID,
			Txid:     child.TxHash(),
		},
	)
	require.NoError(t, err)

	err = store.DeleteUnminedTx(
		t.Context(),
		db.DeleteUnminedTxParams{
			WalletID: walletID,
			Txid:     parent.TxHash(),
		},
	)
	require.NoError(t, err)

	for _, tx := range []*wire.MsgTx{parent, child} {
		_, err = store.GetTx(
			t.Context(),
			db.GetTxQuery{WalletID: walletID, Txid: tx.TxHash()},
		)
		require.ErrorIs(t, err, db.ErrTxNotFound)
	}

	// With no rows left behind, the chain can record both again.
	confirming := CreateBlockFixture(t, store.Queries(), 451)
	for i, tx := range []*wire.MsgTx{parent, child} {
		err = store.CreateTx(
			t.Context(),
			db.CreateTxParams{
				WalletID: walletID,
				Tx:       tx,
				Received: time.Unix(int64(1710004420+i), 0),
				Block:    &confirming,
				Status:   db.TxStatusPublished,
				Credits:  map[uint32]address.Address{0: nil},
			},
		)
		require.NoError(t, err)
	}
}

// TestDeleteUnminedTxClearsLeaseAndReplacement verifies that removing a branch
// takes the lease and replacement rows that depend on it, rather than failing
// on them or leaving them behind.
func TestDeleteUnminedTxClearsLeaseAndReplacement(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-unmined-dependents")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	block := CreateBlockFixture(t, store.Queries(), 460)

	funding := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 9000, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       funding,
			Received: time.Unix(1710004500, 0),
			Block:    &block,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	root := newRegularTx(
		[]wire.OutPoint{{Hash: funding.TxHash()}},
		[]*wire.TxOut{{Value: 8000, PkScript: addr.ScriptPubKey}},
	)

	child := newRegularTx(
		[]wire.OutPoint{{Hash: root.TxHash()}},
		[]*wire.TxOut{{Value: 7000, PkScript: addr.ScriptPubKey}},
	)
	for i, tx := range []*wire.MsgTx{root, child} {
		err = store.CreateTx(
			t.Context(),
			db.CreateTxParams{
				WalletID: walletID,
				Tx:       tx,
				Received: time.Unix(int64(1710004510+i), 0),
				Status:   db.TxStatusPublished,
				Credits:  map[uint32]address.Address{0: nil},
			},
		)
		require.NoError(t, err)
	}

	// Lease the branch tip, which the removal must drop with its UTXO.
	tipOutput := wire.OutPoint{Hash: child.TxHash(), Index: 0}
	_, err = store.LeaseOutput(
		t.Context(),
		db.LeaseOutputParams{
			WalletID: walletID,
			ID:       [32]byte{9},
			OutPoint: tipOutput,
			Duration: time.Hour,
		},
	)
	require.NoError(t, err)

	// Record a replacement edge between two branch members, which the
	// removal must drop with their rows.
	rootID, ok := txIDByHash(t, store, walletID, root.TxHash())
	require.True(t, ok)
	childID, ok := txIDByHash(t, store, walletID, child.TxHash())
	require.True(t, ok)
	insertReplacementEdge(t, store, walletID, rootID, childID)

	require.True(t, walletUtxoExists(t, store, walletID, tipOutput))
	require.NotZero(t, leaseRows(t, store, walletID))
	require.NotZero(t, replacementRows(t, store, walletID))

	err = store.DeleteUnminedTx(
		t.Context(),
		db.DeleteUnminedTxParams{
			WalletID: walletID,
			Txid:     root.TxHash(),
		},
	)
	require.NoError(t, err)

	require.Zero(t, leaseRows(t, store, walletID))
	require.Zero(t, replacementRows(t, store, walletID))
	require.False(t, walletUtxoExists(t, store, walletID, tipOutput))
}

// TestDeleteUnminedTxRollsBackOnFailure verifies that a write which fails
// partway through leaves the branch exactly as it was, rather than half
// removed.
func TestDeleteUnminedTxRollsBackOnFailure(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-unmined-rollback")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	block := CreateBlockFixture(t, store.Queries(), 470)

	funding := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 9000, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       funding,
			Received: time.Unix(1710004600, 0),
			Block:    &block,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	rootInput := wire.OutPoint{Hash: funding.TxHash()}
	root := newRegularTx(
		[]wire.OutPoint{rootInput},
		[]*wire.TxOut{{Value: 8000, PkScript: addr.ScriptPubKey}},
	)

	child := newRegularTx(
		[]wire.OutPoint{{Hash: root.TxHash()}},
		[]*wire.TxOut{{Value: 7000, PkScript: addr.ScriptPubKey}},
	)
	for i, tx := range []*wire.MsgTx{root, child} {
		err = store.CreateTx(
			t.Context(),
			db.CreateTxParams{
				WalletID: walletID,
				Tx:       tx,
				Received: time.Unix(int64(1710004610+i), 0),
				Status:   db.TxStatusPublished,
				Credits:  map[uint32]address.Address{0: nil},
			},
		)
		require.NoError(t, err)
	}

	// The root row is removed last, so aborting it fails the write after the
	// descendant has already gone inside the same transaction.
	rejectBranchRowDelete(t, store, root.TxHash())

	err = store.DeleteUnminedTx(
		t.Context(),
		db.DeleteUnminedTxParams{
			WalletID: walletID,
			Txid:     root.TxHash(),
		},
	)
	require.Error(t, err)
	require.NotErrorIs(t, err, db.ErrTxNotFound)
	require.NotErrorIs(t, err, db.ErrDeleteRequiresUnmined)

	// Nothing moved: both rows stand, the branch still claims the funding
	// output, and the tip it created is still a wallet coin.
	for _, tx := range []*wire.MsgTx{root, child} {
		info, err := store.GetTx(
			t.Context(),
			db.GetTxQuery{WalletID: walletID, Txid: tx.TxHash()},
		)
		require.NoError(t, err)
		require.Equal(t, db.TxStatusPublished, info.Status)
	}

	require.True(t, walletUtxoSpent(t, store, walletID, rootInput))
	require.True(t, walletUtxoExists(t, store, walletID, wire.OutPoint{
		Hash: child.TxHash(), Index: 0,
	}))
}

// TestDeleteUnminedTxRejectsTerminalRoot verifies that a root the wallet
// already made terminal reports the same missing-tx identity every backend
// gives, rather than a SQL-only invalid-state identity for a row kvdb would
// not hold at all.
func TestDeleteUnminedTxRejectsTerminalRoot(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-delete-unmined-terminal")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")

	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	block := CreateBlockFixture(t, store.Queries(), 460)

	funding := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 9000, PkScript: addr.ScriptPubKey}},
	)
	err := store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       funding,
			Received: time.Unix(1710004500, 0),
			Block:    &block,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	spend := newRegularTx(
		[]wire.OutPoint{{Hash: funding.TxHash()}},
		[]*wire.TxOut{{Value: 8000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(
		t.Context(),
		db.CreateTxParams{
			WalletID: walletID,
			Tx:       spend,
			Received: time.Unix(1710004510, 0),
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	err = store.InvalidateUnminedTx(
		t.Context(),
		db.InvalidateUnminedTxParams{
			WalletID: walletID,
			Txid:     spend.TxHash(),
		},
	)
	require.NoError(t, err)

	err = store.DeleteUnminedTx(
		t.Context(),
		db.DeleteUnminedTxParams{
			WalletID: walletID,
			Txid:     spend.TxHash(),
		},
	)
	require.ErrorIs(t, err, db.ErrTxNotFound)
	require.NotErrorIs(t, err, db.ErrDeleteRequiresUnmined)

	// The retained row is untouched by the refusal.
	info, err := store.GetTx(
		t.Context(),
		db.GetTxQuery{WalletID: walletID, Txid: spend.TxHash()},
	)
	require.NoError(t, err)
	require.Equal(t, db.TxStatusFailed, info.Status)
}
