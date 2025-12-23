//go:build itest

package itest

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestCreateTx verifies that CreateTx correctly creates a transaction record.
func TestCreateTx(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	// Create a wallet first.
	walletParams := CreateWalletParamsFixture("tx-test-wallet")
	walletInfo, err := store.CreateWallet(t.Context(), walletParams)
	require.NoError(t, err)

	// Create a test transaction.
	tx := createTestTransaction(t, 2, 1)
	params := db.CreateTxParams{
		WalletID: walletInfo.ID,
		Tx:       tx,
		Label:    "test transaction",
		Credits:  []db.CreditData{},
	}

	err = store.CreateTx(t.Context(), params)
	require.NoError(t, err)

	// Verify the transaction was created by fetching it.
	txHash := tx.TxHash()
	getQuery := db.GetTxQuery{
		WalletID: walletInfo.ID,
		Txid:     txHash,
	}

	txInfo, err := store.GetTx(t.Context(), getQuery)
	require.NoError(t, err)
	require.NotNil(t, txInfo)
	require.Equal(t, txHash, txInfo.Hash)
	require.Equal(t, "test transaction", txInfo.Label)
	require.Nil(t, txInfo.Block, "transaction should be unconfirmed")
}

// TestGetTx_NotFound verifies that GetTx returns an error when the
// transaction doesn't exist.
func TestGetTx_NotFound(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	walletParams := CreateWalletParamsFixture("tx-notfound-wallet")
	walletInfo, err := store.CreateWallet(t.Context(), walletParams)
	require.NoError(t, err)

	query := db.GetTxQuery{
		WalletID: walletInfo.ID,
		Txid:     RandomHash(),
	}

	_, err = store.GetTx(t.Context(), query)
	require.Error(t, err)
	require.ErrorContains(t, err, "not found")
}

// TestUpdateTx_Label verifies that UpdateTx correctly updates a transaction
// label.
func TestUpdateTx_Label(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	walletParams := CreateWalletParamsFixture("tx-update-wallet")
	walletInfo, err := store.CreateWallet(t.Context(), walletParams)
	require.NoError(t, err)

	// Create a transaction.
	tx := createTestTransaction(t, 1, 1)
	createParams := db.CreateTxParams{
		WalletID: walletInfo.ID,
		Tx:       tx,
		Label:    "original label",
		Credits:  []db.CreditData{},
	}
	err = store.CreateTx(t.Context(), createParams)
	require.NoError(t, err)

	// Update the label.
	txHash := tx.TxHash()
	newLabel := "updated label"
	updateParams := db.UpdateTxParams{
		WalletID: walletInfo.ID,
		Txid:     txHash,
		Label:    &newLabel,
	}

	err = store.UpdateTx(t.Context(), updateParams)
	require.NoError(t, err)

	// Verify the label was updated.
	getQuery := db.GetTxQuery{
		WalletID: walletInfo.ID,
		Txid:     txHash,
	}
	txInfo, err := store.GetTx(t.Context(), getQuery)
	require.NoError(t, err)
	require.Equal(t, newLabel, txInfo.Label)
}

// TestUpdateTx_Block verifies that UpdateTx correctly confirms a transaction
// by setting its block.
func TestUpdateTx_Block(t *testing.T) {
	t.Parallel()

	store, dbConn := NewTestStore(t)

	walletParams := CreateWalletParamsFixture("tx-confirm-wallet")
	walletInfo, err := store.CreateWallet(t.Context(), walletParams)
	require.NoError(t, err)

	// Create an unconfirmed transaction.
	tx := createTestTransaction(t, 1, 1)
	createParams := db.CreateTxParams{
		WalletID: walletInfo.ID,
		Tx:       tx,
		Label:    "unconfirmed tx",
		Credits:  []db.CreditData{},
	}
	err = store.CreateTx(t.Context(), createParams)
	require.NoError(t, err)

	// Create a block.
	block := CreateBlockFixture(t, dbConn, 100)

	// Confirm the transaction.
	txHash := tx.TxHash()
	updateParams := db.UpdateTxParams{
		WalletID: walletInfo.ID,
		Txid:     txHash,
		Block:    &block,
	}

	err = store.UpdateTx(t.Context(), updateParams)
	require.NoError(t, err)

	// Verify the transaction is now confirmed.
	getQuery := db.GetTxQuery{
		WalletID: walletInfo.ID,
		Txid:     txHash,
	}
	txInfo, err := store.GetTx(t.Context(), getQuery)
	require.NoError(t, err)
	require.NotNil(t, txInfo.Block)
	require.Equal(t, block.Height, txInfo.Block.Height)
	require.Equal(t, block.Hash, txInfo.Block.Hash)
}

// TestListTxns_UnminedOnly verifies that ListTxns correctly returns only
// unconfirmed transactions.
func TestListTxns_UnminedOnly(t *testing.T) {
	t.Parallel()

	store, dbConn := NewTestStore(t)

	walletParams := CreateWalletParamsFixture("tx-list-wallet")
	walletInfo, err := store.CreateWallet(t.Context(), walletParams)
	require.NoError(t, err)

	// Create some unconfirmed transactions.
	for i := 0; i < 3; i++ {
		tx := createTestTransaction(t, i+1, 1)
		params := db.CreateTxParams{
			WalletID: walletInfo.ID,
			Tx:       tx,
			Label:    "",
			Credits:  []db.CreditData{},
		}
		err = store.CreateTx(t.Context(), params)
		require.NoError(t, err)
	}

	// Create a confirmed transaction.
	block := CreateBlockFixture(t, dbConn, 200)
	tx := createTestTransaction(t, 10, 1)
	params := db.CreateTxParams{
		WalletID: walletInfo.ID,
		Tx:       tx,
		Label:    "",
		Credits:  []db.CreditData{},
	}
	err = store.CreateTx(t.Context(), params)
	require.NoError(t, err)

	txHash := tx.TxHash()
	updateParams := db.UpdateTxParams{
		WalletID: walletInfo.ID,
		Txid:     txHash,
		Block:    &block,
	}
	err = store.UpdateTx(t.Context(), updateParams)
	require.NoError(t, err)

	// List only unmined transactions.
	query := db.ListTxnsQuery{
		WalletID:    walletInfo.ID,
		UnminedOnly: true,
		StartHeight: 0,
		EndHeight:   0,
	}

	txns, err := store.ListTxns(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, txns, 3, "should only return unconfirmed txs")

	// Verify all returned transactions are unconfirmed.
	for _, txInfo := range txns {
		require.Nil(t, txInfo.Block)
	}
}

// TestListTxns_ByHeightRange verifies that ListTxns correctly returns
// transactions within a block height range.
func TestListTxns_ByHeightRange(t *testing.T) {
	t.Parallel()

	store, dbConn := NewTestStore(t)

	walletParams := CreateWalletParamsFixture("tx-range-wallet")
	walletInfo, err := store.CreateWallet(t.Context(), walletParams)
	require.NoError(t, err)

	// Create blocks at different heights.
	block100 := CreateBlockFixture(t, dbConn, 100)
	block200 := CreateBlockFixture(t, dbConn, 200)
	block300 := CreateBlockFixture(t, dbConn, 300)

	blocks := []db.Block{block100, block200, block300}

	// Create a transaction in each block.
	for i, block := range blocks {
		tx := createTestTransaction(t, i+1, 1)
		params := db.CreateTxParams{
			WalletID: walletInfo.ID,
			Tx:       tx,
			Label:    "",
			Credits:  []db.CreditData{},
		}
		err = store.CreateTx(t.Context(), params)
		require.NoError(t, err)

		txHash := tx.TxHash()
		updateParams := db.UpdateTxParams{
			WalletID: walletInfo.ID,
			Txid:     txHash,
			Block:    &block,
		}
		err = store.UpdateTx(t.Context(), updateParams)
		require.NoError(t, err)
	}

	// Query transactions between height 100 and 200.
	query := db.ListTxnsQuery{
		WalletID:    walletInfo.ID,
		UnminedOnly: false,
		StartHeight: 100,
		EndHeight:   200,
	}

	txns, err := store.ListTxns(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, txns, 2, "should return 2 txs in range 100-200")

	// Verify the heights.
	require.Equal(t, uint32(100), txns[0].Block.Height)
	require.Equal(t, uint32(200), txns[1].Block.Height)
}

// TestDeleteTx verifies that DeleteTx correctly removes an unconfirmed
// transaction.
func TestDeleteTx(t *testing.T) {
	t.Parallel()

	store, _ := NewTestStore(t)

	walletParams := CreateWalletParamsFixture("tx-delete-wallet")
	walletInfo, err := store.CreateWallet(t.Context(), walletParams)
	require.NoError(t, err)

	// Create an unconfirmed transaction.
	tx := createTestTransaction(t, 1, 1)
	createParams := db.CreateTxParams{
		WalletID: walletInfo.ID,
		Tx:       tx,
		Label:    "to be deleted",
		Credits:  []db.CreditData{},
	}
	err = store.CreateTx(t.Context(), createParams)
	require.NoError(t, err)

	// Delete the transaction.
	txHash := tx.TxHash()
	deleteParams := db.DeleteTxParams{
		WalletID: walletInfo.ID,
		Txid:     txHash,
	}

	err = store.DeleteTx(t.Context(), deleteParams)
	require.NoError(t, err)

	// Verify the transaction was deleted.
	getQuery := db.GetTxQuery{
		WalletID: walletInfo.ID,
		Txid:     txHash,
	}
	_, err = store.GetTx(t.Context(), getQuery)
	require.Error(t, err)
	require.ErrorContains(t, err, "not found")
}

// TestRollbackToBlock verifies that RollbackToBlock correctly unconfirms
// transactions and deletes blocks.
func TestRollbackToBlock(t *testing.T) {
	t.Parallel()

	store, dbConn := NewTestStore(t)

	walletParams := CreateWalletParamsFixture("tx-rollback-wallet")
	walletInfo, err := store.CreateWallet(t.Context(), walletParams)
	require.NoError(t, err)

	// Create blocks at different heights.
	block100 := CreateBlockFixture(t, dbConn, 100)
	block200 := CreateBlockFixture(t, dbConn, 200)
	block300 := CreateBlockFixture(t, dbConn, 300)

	blocks := []db.Block{block100, block200, block300}
	txHashes := make([]chainhash.Hash, 3)

	// Create a transaction in each block.
	for i, block := range blocks {
		tx := createTestTransaction(t, i+1, 1)
		params := db.CreateTxParams{
			WalletID: walletInfo.ID,
			Tx:       tx,
			Label:    "",
			Credits:  []db.CreditData{},
		}
		err = store.CreateTx(t.Context(), params)
		require.NoError(t, err)

		txHash := tx.TxHash()
		txHashes[i] = txHash

		updateParams := db.UpdateTxParams{
			WalletID: walletInfo.ID,
			Txid:     txHash,
			Block:    &block,
		}
		err = store.UpdateTx(t.Context(), updateParams)
		require.NoError(t, err)
	}

	// Rollback to height 200 (should unconfirm blocks 200 and 300).
	err = store.RollbackToBlock(t.Context(), 200)
	require.NoError(t, err)

	// Verify transaction at height 100 is still confirmed.
	getQuery := db.GetTxQuery{
		WalletID: walletInfo.ID,
		Txid:     txHashes[0],
	}
	txInfo, err := store.GetTx(t.Context(), getQuery)
	require.NoError(t, err)
	require.NotNil(t, txInfo.Block)
	require.Equal(t, uint32(100), txInfo.Block.Height)

	// Verify transactions at heights 200 and 300 are now unconfirmed.
	for i := 1; i <= 2; i++ {
		getQuery := db.GetTxQuery{
			WalletID: walletInfo.ID,
			Txid:     txHashes[i],
		}
		txInfo, err := store.GetTx(t.Context(), getQuery)
		require.NoError(t, err)
		require.Nil(
			t, txInfo.Block,
			"tx should be unconfirmed after rollback",
		)
	}
}

// createTestTransaction creates a wire.MsgTx for testing with the specified
// number of inputs and outputs.
func createTestTransaction(t *testing.T, numInputs,
	numOutputs int) *wire.MsgTx {
	t.Helper()

	tx := wire.NewMsgTx(wire.TxVersion)

	// Add inputs.
	for i := 0; i < numInputs; i++ {
		prevHash := RandomHash()
		outPoint := wire.NewOutPoint(&prevHash, uint32(i))
		txIn := wire.NewTxIn(outPoint, nil, nil)
		tx.AddTxIn(txIn)
	}

	// Add outputs.
	for i := 0; i < numOutputs; i++ {
		pkScript := RandomBytes(25)
		txOut := wire.NewTxOut(1000000, pkScript)
		tx.AddTxOut(txOut)
	}

	return tx
}
