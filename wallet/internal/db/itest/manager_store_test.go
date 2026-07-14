package itest

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

type managerStoreHarness struct {
	conn     *sql.DB
	postgres bool
	newStore func(int64) db.Store
}

func testManagerStore(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	t.Run("manager transaction", func(t *testing.T) {
		testManagerTransaction(t, harness)
	})
	t.Run("rollback", func(t *testing.T) {
		testRollback(t, harness)
	})
	t.Run("rollback transaction", func(t *testing.T) {
		testRollbackTransaction(t, harness)
	})
	t.Run("duplicate incidence", func(t *testing.T) {
		testDuplicateIncidence(t, harness)
	})
	t.Run("birthday verification", func(t *testing.T) {
		testBirthdayVerification(t, harness)
	})
}

func testManagerTransaction(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	start := testBlock(100)
	synced := testBlock(101)
	walletID := harness.createWallet(t, "manager-transaction", start, synced)
	store := harness.newStore(walletID)

	var resetCount int

	err := store.View(ctx, func(tx db.ReadTx) error {
		hash, err := tx.Addr().BlockHash(start.Height)
		require.NoError(t, err)
		require.Equal(t, start.Hash, *hash)

		return nil
	}, func() {
		resetCount++
	})
	require.NoError(t, err)
	require.Equal(t, 1, resetCount)

	missingHeight := int32(99)
	err = store.View(ctx, func(tx db.ReadTx) error {
		_, err := tx.Addr().BlockHash(missingHeight)
		require.True(t, waddrmgr.IsError(err, waddrmgr.ErrBlockNotFound))

		return nil
	}, func() {})
	require.NoError(t, err)

	replacement := testBlock(101)
	replacement.Hash = testHash(201)
	replacement.Timestamp = time.Unix(2201, 0)
	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Addr().SetSyncedTo(&replacement)
	}, func() {})
	require.NoError(t, err)

	require.Equal(t, replacement.Height, harness.syncedHeight(t, walletID))
	require.Equal(t, replacement.Hash, harness.blockHash(t, replacement.Height))

	err = store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Addr().SetSyncedTo(nil)
	}, func() {})
	require.NoError(t, err)
	require.Equal(t, start.Height, harness.syncedHeight(t, walletID))

	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()

	var bodyCalled bool

	err = store.Update(canceledCtx, func(db.ReadWriteTx) error {
		bodyCalled = true

		return nil
	}, func() {})
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, bodyCalled)
}

func testRollback(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	walletID := harness.createWallet(
		t, "rollback", testBlock(200), testBlock(201),
	)
	store := harness.newStore(walletID)

	fundingHash := testHash(21)
	fundingID := harness.insertTransaction(
		t, walletID, fundingHash, 200, 0, false,
	)
	fundingCreditID := harness.insertCredit(t, walletID, fundingID)
	harness.setActiveCredit(t, walletID, fundingCreditID)

	spenderHash := testHash(22)
	spenderID := harness.insertTransaction(
		t, walletID, spenderHash, 201, 0, false,
	)
	harness.insertInput(t, spenderID, 0, fundingHash, 0)
	harness.insertCreditSpend(t, walletID, fundingCreditID, spenderID, 0)

	coinbaseHash := testHash(23)
	coinbaseID := harness.insertTransaction(
		t, walletID, coinbaseHash, 200, 1, true,
	)
	coinbaseCreditID := harness.insertCredit(t, walletID, coinbaseID)
	harness.setActiveCredit(t, walletID, coinbaseCreditID)

	childHash := testHash(24)
	childID := harness.insertUnminedTransaction(t, walletID, childHash)
	harness.insertInput(t, childID, 0, coinbaseHash, 0)
	childCreditID := harness.insertCredit(t, walletID, childID)
	harness.setActiveCredit(t, walletID, childCreditID)

	grandchildHash := testHash(25)
	grandchildID := harness.insertUnminedTransaction(
		t, walletID, grandchildHash,
	)
	harness.insertInput(t, grandchildID, 0, childHash, 0)

	err := store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Tx().Rollback(200)
	}, func() {})
	require.NoError(t, err)

	require.False(t, harness.transactionMined(t, fundingID))
	require.False(t, harness.transactionMined(t, spenderID))
	require.True(t, harness.transactionExists(t, fundingID))
	require.True(t, harness.transactionExists(t, spenderID))
	require.False(t, harness.transactionExists(t, coinbaseID))
	require.False(t, harness.transactionExists(t, childID))
	require.False(t, harness.transactionExists(t, grandchildID))
	require.Equal(t, int64(0), harness.creditSpendCount(t, walletID))
	require.Equal(t, fundingCreditID, harness.activeCreditID(
		t, walletID, fundingHash, 0,
	))
}

func testRollbackTransaction(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	start := testBlock(300)
	synced := testBlock(301)
	walletID := harness.createWallet(t, "rollback-transaction", start, synced)
	store := harness.newStore(walletID)

	txID := harness.insertTransaction(
		t, walletID, testHash(31), 301, 0, false,
	)
	testErr := errors.New("abort manager transaction")

	err := store.Update(ctx, func(tx db.ReadWriteTx) error {
		err := tx.Addr().SetSyncedTo(&start)
		if err != nil {
			return err
		}

		err = tx.Tx().Rollback(301)
		if err != nil {
			return err
		}

		return testErr
	}, func() {})
	require.ErrorIs(t, err, testErr)
	require.Equal(t, synced.Height, harness.syncedHeight(t, walletID))
	require.True(t, harness.transactionMined(t, txID))
}

func testDuplicateIncidence(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	ctx := context.Background()
	walletID := harness.createWallet(
		t, "duplicate-incidence", testBlock(400), testBlock(401),
	)
	store := harness.newStore(walletID)

	hash := testHash(41)
	lowerID := harness.insertTransaction(t, walletID, hash, 400, 0, false)
	lowerCreditID := harness.insertCredit(t, walletID, lowerID)
	higherID := harness.insertTransaction(t, walletID, hash, 401, 0, false)
	higherCreditID := harness.insertCredit(t, walletID, higherID)
	harness.setActiveCredit(t, walletID, lowerCreditID)

	err := store.Update(ctx, func(tx db.ReadWriteTx) error {
		return tx.Tx().Rollback(400)
	}, func() {})
	require.NoError(t, err)

	require.False(t, harness.transactionExists(t, lowerID))
	require.True(t, harness.transactionExists(t, higherID))
	require.False(t, harness.transactionMined(t, higherID))
	require.Equal(t, higherCreditID, harness.activeCreditID(
		t, walletID, hash, 0,
	))
}

func testBirthdayVerification(t *testing.T, harness *managerStoreHarness) {
	t.Helper()

	block := testBlock(500)
	walletID := harness.createWallet(
		t, "birthday-verification", block, block,
	)

	harness.exec(t, `
		UPDATE wallet_sync_states
		SET birthday_block_height = ?, birthday_block_verified = TRUE
		WHERE wallet_id = ?
	`, block.Height, walletID)
	harness.exec(t, `
		UPDATE wallet_sync_states
		SET birthday_block_height = NULL
		WHERE wallet_id = ?
	`, walletID)

	var verified bool

	err := harness.queryRow(t, `
		SELECT birthday_block_verified
		FROM wallet_sync_states
		WHERE wallet_id = ?
	`, walletID).Scan(&verified)
	require.NoError(t, err)
	require.True(t, verified)
}

func (h *managerStoreHarness) createWallet(t *testing.T, name string,
	start, synced waddrmgr.BlockStamp) int64 {

	t.Helper()
	h.putBlock(t, start)
	h.putBlock(t, synced)

	var walletID int64

	err := h.queryRow(t, `
		INSERT INTO wallets (
			wallet_name, manager_version, manager_created_at,
			is_watch_only, master_pub_params, encrypted_crypto_pub_key
		) VALUES (?, 1, 1, TRUE, ?, ?)
		RETURNING id
	`, name, []byte{1}, []byte{2}).Scan(&walletID)
	require.NoError(t, err)

	h.exec(t, `
		INSERT INTO wallet_sync_states (
			wallet_id, start_block_height, synced_block_height,
			birthday_timestamp, birthday_block_verified
		) VALUES (?, ?, ?, 1, FALSE)
	`, walletID, start.Height, synced.Height)

	return walletID
}

func (h *managerStoreHarness) putBlock(t *testing.T,
	block waddrmgr.BlockStamp) {

	t.Helper()
	h.exec(t, `
		INSERT INTO blocks (block_height, header_hash, block_timestamp)
		VALUES (?, ?, ?)
		ON CONFLICT (block_height) DO UPDATE SET
			header_hash = excluded.header_hash,
			block_timestamp = excluded.block_timestamp
	`, block.Height, block.Hash[:], block.Timestamp.Unix())
}

func (h *managerStoreHarness) insertTransaction(t *testing.T, walletID int64,
	hash chainhash.Hash, height int32, order int64, coinbase bool) int64 {

	t.Helper()

	var transactionID int64

	err := h.queryRow(t, `
		INSERT INTO transactions (
			wallet_id, tx_hash, raw_tx, received_unix, block_height,
			confirmed_order, is_coinbase
		) VALUES (?, ?, ?, 1, ?, ?, ?)
		RETURNING id
	`, walletID, hash[:], []byte{hash[0]}, height, order, coinbase).
		Scan(&transactionID)
	require.NoError(t, err)

	return transactionID
}

func (h *managerStoreHarness) insertUnminedTransaction(t *testing.T,
	walletID int64, hash chainhash.Hash) int64 {

	t.Helper()

	var transactionID int64

	err := h.queryRow(t, `
		INSERT INTO transactions (
			wallet_id, tx_hash, raw_tx, received_unix, is_coinbase
		) VALUES (?, ?, ?, 1, FALSE)
		RETURNING id
	`, walletID, hash[:], []byte{hash[0]}).Scan(&transactionID)
	require.NoError(t, err)

	return transactionID
}

func (h *managerStoreHarness) insertInput(t *testing.T, transactionID int64,
	inputIndex int64, prevHash chainhash.Hash, prevIndex int64) {

	t.Helper()
	h.exec(t, `
		INSERT INTO transaction_inputs (
			spending_tx_id, input_index, prev_tx_hash, prev_output_index
		) VALUES (?, ?, ?, ?)
	`, transactionID, inputIndex, prevHash[:], prevIndex)
}

func (h *managerStoreHarness) insertCredit(t *testing.T, walletID,
	transactionID int64) int64 {

	t.Helper()

	var creditID int64

	err := h.queryRow(t, `
		INSERT INTO credits (
			wallet_id, transaction_id, output_index, amount, pk_script,
			is_change
		) VALUES (?, ?, ?, 1000, ?, FALSE)
		RETURNING id
	`, walletID, transactionID, 0, []byte{0x51}).Scan(&creditID)
	require.NoError(t, err)

	return creditID
}

func (h *managerStoreHarness) setActiveCredit(t *testing.T, walletID,
	creditID int64) {

	t.Helper()
	h.exec(t, `
		INSERT INTO active_credit_incidences (
			wallet_id, tx_hash, output_index, credit_id
		)
		SELECT c.wallet_id, tx.tx_hash, c.output_index, c.id
		FROM credits AS c
		INNER JOIN transactions AS tx ON tx.id = c.transaction_id
		WHERE c.wallet_id = ? AND c.id = ?
		ON CONFLICT (wallet_id, tx_hash, output_index) DO UPDATE SET
			credit_id = excluded.credit_id
	`, walletID, creditID)
}

func (h *managerStoreHarness) insertCreditSpend(t *testing.T, walletID,
	creditID, transactionID, inputIndex int64) {

	t.Helper()
	h.exec(t, `
		INSERT INTO credit_spends (
			wallet_id, credit_id, spending_tx_id, input_index
		) VALUES (?, ?, ?, ?)
	`, walletID, creditID, transactionID, inputIndex)
}

func (h *managerStoreHarness) syncedHeight(t *testing.T,
	walletID int64) int32 {

	t.Helper()

	var height int32

	err := h.queryRow(t, `
		SELECT synced_block_height FROM wallet_sync_states
		WHERE wallet_id = ?
	`, walletID).Scan(&height)
	require.NoError(t, err)

	return height
}

func (h *managerStoreHarness) blockHash(t *testing.T,
	height int32) chainhash.Hash {

	t.Helper()

	var hashBytes []byte

	err := h.queryRow(t, `
		SELECT header_hash FROM blocks WHERE block_height = ?
	`, height).Scan(&hashBytes)
	require.NoError(t, err)

	hash, err := chainhash.NewHash(hashBytes)
	require.NoError(t, err)

	return *hash
}

func (h *managerStoreHarness) transactionExists(t *testing.T,
	transactionID int64) bool {

	t.Helper()

	var count int64

	err := h.queryRow(t, `
		SELECT count(*) FROM transactions WHERE id = ?
	`, transactionID).Scan(&count)
	require.NoError(t, err)

	return count == 1
}

func (h *managerStoreHarness) transactionMined(t *testing.T,
	transactionID int64) bool {

	t.Helper()

	var mined bool

	err := h.queryRow(t, `
		SELECT block_height IS NOT NULL FROM transactions WHERE id = ?
	`, transactionID).Scan(&mined)
	require.NoError(t, err)

	return mined
}

func (h *managerStoreHarness) creditSpendCount(t *testing.T,
	walletID int64) int64 {

	t.Helper()

	var count int64

	err := h.queryRow(t, `
		SELECT count(*) FROM credit_spends WHERE wallet_id = ?
	`, walletID).Scan(&count)
	require.NoError(t, err)

	return count
}

func (h *managerStoreHarness) activeCreditID(t *testing.T, walletID int64,
	hash chainhash.Hash, outputIndex int64) int64 {

	t.Helper()

	var creditID int64

	err := h.queryRow(t, `
		SELECT credit_id FROM active_credit_incidences
		WHERE wallet_id = ? AND tx_hash = ? AND output_index = ?
	`, walletID, hash[:], outputIndex).Scan(&creditID)
	require.NoError(t, err)

	return creditID
}

func (h *managerStoreHarness) exec(t *testing.T, query string,
	args ...any) {

	t.Helper()

	_, err := h.conn.ExecContext(
		context.Background(), h.bind(query), args...,
	)
	require.NoError(t, err)
}

func (h *managerStoreHarness) queryRow(t *testing.T, query string,
	args ...any) *sql.Row {

	t.Helper()

	return h.conn.QueryRowContext(
		context.Background(), h.bind(query), args...,
	)
}

func (h *managerStoreHarness) bind(query string) string {
	if !h.postgres {
		return query
	}

	var builder strings.Builder

	parameter := 1
	for _, char := range query {
		if char != '?' {
			builder.WriteRune(char)

			continue
		}

		builder.WriteString(fmt.Sprintf("$%d", parameter))
		parameter++
	}

	return builder.String()
}

func testBlock(height int32) waddrmgr.BlockStamp {
	var hash chainhash.Hash

	hash[0] = 0xff
	binary.BigEndian.PutUint32(hash[1:5], uint32(height))

	return waddrmgr.BlockStamp{
		Height:    height,
		Hash:      hash,
		Timestamp: time.Unix(1000+int64(height), 0),
	}
}

func testHash(value byte) chainhash.Hash {
	var hash chainhash.Hash
	for i := range hash {
		hash[i] = value
	}

	return hash
}
