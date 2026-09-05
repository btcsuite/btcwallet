//go:build itest && test_db_postgres

package itest

import (
	"testing"
	"time"

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
