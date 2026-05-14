package sqlite

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
	"github.com/stretchr/testify/require"
)

// TestListTxDetailsReturnsRowsWithoutBlock verifies that the detail
// path returns the same no-confirming-block history as the summary
// path, including retained failed rows.
func TestListTxDetailsReturnsRowsWithoutBlock(t *testing.T) {
	t.Parallel()

	// Arrange: Create one confirmed transaction plus two rows
	// without confirming blocks, one still pending and one
	// retained as failed history.
	store, cleanup := newTestStore(t)
	t.Cleanup(cleanup)

	wallet, err := store.CreateWallet(
		t.Context(), testWalletParams("wallet-list-tx-details-without-block"),
	)
	require.NoError(t, err)

	confirmedBlock := &db.Block{
		Hash:      chainhash.Hash{90},
		Height:    200,
		Timestamp: time.Unix(1710000790, 0),
	}

	err = store.execWrite(t.Context(), func(qtx *sqlc.Queries) error {
		return ensureBlockExists(t.Context(), qtx, confirmedBlock)
	})
	require.NoError(t, err)

	confirmedTx := newListTxDetailsTestTx(1, 7_000, 0x51)
	unminedTx := newListTxDetailsTestTx(2, 8_000, 0x52)
	failedTx := newListTxDetailsTestTx(3, 8_100, 0x53)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: wallet.ID,
		Tx:       confirmedTx,
		Received: time.Unix(1710000800, 0),
		Block:    confirmedBlock,
		Status:   db.TxStatusPublished,
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: wallet.ID,
		Tx:       unminedTx,
		Received: time.Unix(1710000810, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: wallet.ID,
		Tx:       failedTx,
		Received: time.Unix(1710000815, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	err = store.execWrite(t.Context(), func(qtx *sqlc.Queries) error {
		failedHash := failedTx.TxHash()

		meta, err := qtx.GetTransactionMetaByHash(
			t.Context(), sqlc.GetTransactionMetaByHashParams{
				WalletID: int64(wallet.ID),
				TxHash:   failedHash[:],
			},
		)
		if err != nil {
			return err
		}

		_, err = qtx.UpdateTransactionStatusByIDs(
			t.Context(), sqlc.UpdateTransactionStatusByIDsParams{
				Status:   int64(db.TxStatusFailed),
				WalletID: int64(wallet.ID),
				TxIds:    []int64{meta.ID},
			},
		)

		return err
	})
	require.NoError(t, err)

	// Act: Query the wallet tx-reader unmined range through the detail path.
	details, err := store.ListTxDetails(t.Context(), db.ListTxDetailsQuery{
		WalletID:    wallet.ID,
		StartHeight: -1,
		EndHeight:   -1,
	})

	// Assert: The detail path returns the same rows without
	// confirming blocks as the summary path, including retained
	// failed history.
	require.NoError(t, err)
	require.Len(t, details, 2)

	statusesByHash := make(map[chainhash.Hash]db.TxStatus, len(details))
	for _, detail := range details {
		require.Nil(t, detail.Block)
		statusesByHash[detail.Hash] = detail.Status
	}

	require.Equal(t, db.TxStatusPending, statusesByHash[unminedTx.TxHash()])
	require.Equal(t, db.TxStatusFailed, statusesByHash[failedTx.TxHash()])
}

// newTestStore creates one SQLite store backed by a temporary database file.
func newTestStore(t *testing.T) (*Store, func()) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test.db")

	store, err := NewStore(t.Context(), Config{DBPath: dbPath})
	require.NoError(t, err)

	return store, func() {
		_ = store.Close()
	}
}

// testWalletParams builds one minimal wallet creation request for SQLite tx
// detail tests.
func testWalletParams(name string) db.CreateWalletParams {
	return db.CreateWalletParams{
		Name:                     name,
		ManagerVersion:           1,
		EncryptedMasterPrivKey:   []byte{1},
		MasterPubKey:             []byte{2},
		MasterKeyPrivParams:      []byte{4},
		EncryptedCryptoPrivKey:   []byte{5},
		EncryptedCryptoScriptKey: []byte{7},
	}
}

// newListTxDetailsTestTx builds one deterministic non-coinbase transaction
// fixture with a unique previous outpoint and one output.
func newListTxDetailsTestTx(seed byte, value int64, script byte) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{seed},
	}})
	tx.AddTxOut(&wire.TxOut{Value: value, PkScript: []byte{script}})

	return tx
}
