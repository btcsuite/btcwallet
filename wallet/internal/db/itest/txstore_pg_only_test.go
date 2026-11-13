//go:build itest && test_db_postgres

package itest

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
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

// TestTxGraphChildBeforeConflictPostgres checks that a confirmed conflict also
// removes a child whose write was already in progress.
func TestTxGraphChildBeforeConflictPostgres(t *testing.T) {
	t.Parallel()

	// Arrange: A spends F. B spends A:0 and independent Q. Hold their owned
	// address so B pauses at credit insertion after its graph reads.
	store, childParams, winnerParams := newTxGraphConflict(t)
	walletID := childParams.WalletID
	child := childParams.Tx
	winner := winnerParams.Tx
	f := winner.TxIn[0].PreviousOutPoint
	q := child.TxIn[1].PreviousOutPoint
	rootHash := child.TxIn[0].PreviousOutPoint.Hash
	otherID := newWallet(t, store, "other")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	barrier := lockTxGraphCreditAddress(t, ctx, store.DB(), walletID, q)

	// Act: Pause B at its credit FK, then start W. Another Wallet still
	// accepts a graph write. Release the address and join both calls.
	childCall := startTxGraphCall(
		t, cancel, func() error {
			return store.CreateTx(ctx, childParams)
		},
	)
	waitTxGraphCall(t, ctx, store.DB(), childCall, 1)
	require.NoError(
		t, store.CreateTx(
			ctx, db.CreateTxParams{
				WalletID: otherID,
				Tx:       winner,
				Received: time.Unix(3, 0),
				Status:   db.TxStatusPending,
			},
		),
	)
	winnerCall := startTxGraphCall(
		t, cancel, func() error {
			return store.CreateTx(ctx, winnerParams)
		},
	)
	waitTxGraphCall(t, ctx, store.DB(), winnerCall, 2)
	require.NoError(t, barrier.Rollback())
	require.NoError(t, <-childCall)
	require.NoError(t, <-winnerCall)

	// Assert: W replaces A and fails B. B has no credit, Q is available,
	// and F remains spent by the confirmed winner.
	rootInfo, err := store.GetTx(
		ctx, db.GetTxQuery{
			WalletID: walletID,
			Txid:     rootHash,
		},
	)
	require.NoError(t, err)
	require.Equal(t, db.TxStatusReplaced, rootInfo.Status)
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
	_, err = store.GetUtxo(
		ctx, db.GetUtxoQuery{
			WalletID: walletID,
			OutPoint: f,
		},
	)
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestTxGraphConflictBeforeChildPostgres checks that a child write waits for
// a preceding conflict and then rejects the replaced parent atomically.
func TestTxGraphConflictBeforeChildPostgres(t *testing.T) {
	t.Parallel()

	// Arrange: A spends F and B spends A:0 plus Q. Hold A's row so W stops
	// after descendant discovery while marking the direct root replaced.
	store, childParams, winnerParams := newTxGraphConflict(t)
	walletID := childParams.WalletID
	child := childParams.Tx
	winner := winnerParams.Tx
	f := winner.TxIn[0].PreviousOutPoint
	q := child.TxIn[1].PreviousOutPoint
	childParams.Received = time.Unix(4, 0)
	winnerParams.Received = time.Unix(3, 0)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	barrier := lockTxGraphTransaction(
		t, ctx, store.DB(), walletID, child.TxIn[0].PreviousOutPoint.Hash,
	)

	// Act: Pause W at A's status update, then start B against the same
	// Wallet. Release A and join both calls before reading their results.
	winnerCall := startTxGraphCall(
		t, cancel, func() error {
			return store.CreateTx(ctx, winnerParams)
		},
	)
	waitTxGraphCall(t, ctx, store.DB(), winnerCall, 1)
	childCall := startTxGraphCall(
		t, cancel, func() error {
			return store.CreateTx(ctx, childParams)
		},
	)
	waitTxGraphCall(t, ctx, store.DB(), childCall, 2)
	require.NoError(t, barrier.Rollback())
	require.NoError(t, <-winnerCall)

	err := <-childCall

	// Assert: B rejects its replaced parent and leaves no row or credit.
	// Its independent input Q stays available, while W still spends F.
	require.ErrorIs(t, err, db.ErrTxInputInvalidParent)
	_, err = store.GetTx(
		ctx, db.GetTxQuery{
			WalletID: walletID,
			Txid:     child.TxHash(),
		},
	)
	require.ErrorIs(t, err, db.ErrTxNotFound)
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
	_, err = store.GetUtxo(
		ctx, db.GetUtxoQuery{
			WalletID: walletID,
			OutPoint: f,
		},
	)
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// newTxGraphConflict records funding and unmined A, then builds B and W.
// Both tests share this graph. Each caller controls its barrier and call order.
// Setup uses the test context; callers start operation deadlines afterwards.
func newTxGraphConflict(t *testing.T) (*pgTestStore, db.CreateTxParams,
	db.CreateTxParams) {

	t.Helper()

	// Funding creates F and independent Q. A spends F, B spends A:0 and Q,
	// and confirmed W competes with A for F. Record only funding and A here.
	store := NewTestStore(t)
	walletID := newWallet(t, store, "graph")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "default")
	addr := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "default", false,
	)
	funding := newRegularTx(
		[]wire.OutPoint{randomOutPoint()}, []*wire.TxOut{
			{Value: 6000, PkScript: addr.ScriptPubKey},
			{Value: 7000, PkScript: addr.ScriptPubKey},
		},
	)
	f := wire.OutPoint{Hash: funding.TxHash()}
	q := wire.OutPoint{Hash: funding.TxHash(), Index: 1}
	root := newRegularTx(
		[]wire.OutPoint{f},
		[]*wire.TxOut{{Value: 5000, PkScript: addr.ScriptPubKey}},
	)
	child := newRegularTx(
		[]wire.OutPoint{{Hash: root.TxHash()}, q},
		[]*wire.TxOut{{Value: 11000, PkScript: addr.ScriptPubKey}},
	)
	winner := newRegularTx(
		[]wire.OutPoint{f},
		[]*wire.TxOut{{Value: 5500, PkScript: []byte{0x51}}},
	)
	block := CreateBlockFixture(t, store.Queries(), 1)
	require.NoError(
		t, store.CreateTx(
			t.Context(), db.CreateTxParams{
				WalletID: walletID,
				Tx:       funding,
				Received: time.Unix(1, 0),
				Status:   db.TxStatusPending,
				Credits:  map[uint32]address.Address{0: nil, 1: nil},
			},
		),
	)
	require.NoError(
		t, store.CreateTx(
			t.Context(), db.CreateTxParams{
				WalletID: walletID,
				Tx:       root,
				Received: time.Unix(2, 0),
				Status:   db.TxStatusPending,
				Credits:  map[uint32]address.Address{0: nil},
			},
		),
	)

	// Return ordinary Store parameters so each test can admit the same two
	// writes in its own order without a shared scenario runner.
	childParams := db.CreateTxParams{
		WalletID: walletID,
		Tx:       child,
		Received: time.Unix(3, 0),
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	}
	winnerParams := db.CreateTxParams{
		WalletID: walletID,
		Tx:       winner,
		Received: time.Unix(4, 0),
		Block:    &block,
		Status:   db.TxStatusPublished,
	}

	return store, childParams, winnerParams
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
	barrier := lockTxGraphCreditAddress(t, ctx, store.DB(), walletID, q)

	// Act: Pause B at its credit FK, then start rollback. Release the address
	// after both calls reach SQL. Cleanup cancels and joins on failure too.
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

// lockTxGraphCreditAddress pauses credit insertion at its existing address FK.
// This remains a write boundary after input claims no longer update UTXO rows.
func lockTxGraphCreditAddress(t *testing.T, ctx context.Context, raw *sql.DB,
	walletID uint32, output wire.OutPoint) *sql.Tx {

	t.Helper()

	// Cleanup releases the row even if the test stops before explicit release.
	barrier, err := raw.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = barrier.Rollback() })

	_, err = barrier.ExecContext(
		ctx, `SELECT a.id FROM utxos AS u
		JOIN transactions AS t ON t.id = u.tx_id
		JOIN addresses AS a ON a.id = u.address_id
		WHERE t.wallet_id = $1 AND t.tx_hash = $2 AND u.output_index = $3
		FOR UPDATE OF a`, walletID, output.Hash[:], output.Index,
	)
	require.NoError(t, err)

	return barrier
}

// lockTxGraphTransaction pauses a root write independently of its wallet.
// The second public caller must reach the existing graph ordering boundary.
func lockTxGraphTransaction(t *testing.T, ctx context.Context, raw *sql.DB,
	walletID uint32, txHash chainhash.Hash) *sql.Tx {

	t.Helper()

	// Releasing the barrier is safe even when the test fails before its Act.
	barrier, err := raw.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = barrier.Rollback() })

	_, err = barrier.ExecContext(
		ctx,
		`SELECT id FROM transactions WHERE wallet_id=$1 AND tx_hash=$2
		FOR UPDATE`, walletID, txHash[:],
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

// TestConcurrentTxAdmissionPostgres verifies that overlapping observations of
// one hash replay the first committed row instead of failing its unique key.
func TestConcurrentTxAdmissionPostgres(t *testing.T) {
	t.Parallel()

	for _, method := range []string{
		"CreateTx",
		"ApplyTxBatch",
		"ApplyScanBatch",
	} {
		t.Run(method, func(t *testing.T) {
			// Arrange: Hold an uncommitted matching transaction behind the
			// existing Wallet-row lock. Each public entry point must wait
			// before deciding whether that hash needs a new row.
			store := NewTestStore(t)
			walletID := newWallet(t, store, "concurrent-admission")
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)

			t.Cleanup(cancel)

			barrier, err := store.Pool().Begin(ctx)
			require.NoError(t, err)
			t.Cleanup(func() { _ = barrier.Rollback(ctx) })

			queries := store.Queries().WithTx(barrier)
			_, err = queries.GetWalletForAccountCreation(
				ctx, int64(walletID),
			)
			require.NoError(t, err)

			tx := newRegularTx(
				[]wire.OutPoint{randomOutPoint()},
				[]*wire.TxOut{
					{
						Value:    1000,
						PkScript: []byte{0x51},
					},
				},
			)

			var raw bytes.Buffer
			require.NoError(t, tx.Serialize(&raw))
			hash := tx.TxHash()
			received := time.Unix(1710006000, 0).UTC()
			_, err = queries.InsertTransaction(
				ctx, sqlc.InsertTransactionParams{
					WalletID:     int64(walletID),
					TxHash:       hash[:],
					RawTx:        raw.Bytes(),
					TxStatus:     int16(db.TxStatusPending),
					ReceivedTime: received,
				},
			)
			require.NoError(t, err)

			params := db.CreateTxParams{
				WalletID: walletID,
				Tx:       tx,
				Received: received,
				Status:   db.TxStatusPending,
			}

			// Act: Overlap the public observation with the first writer,
			// using actual SQL lock activity to release it only after the
			// observation reaches the conflicting write boundary.
			result := startTxGraphCall(t, cancel, func() error {
				switch method {
				case "CreateTx":
					return store.CreateTx(ctx, params)
				case "ApplyTxBatch":
					return store.ApplyTxBatch(ctx, db.TxBatchParams{
						WalletID:     walletID,
						Transactions: []db.CreateTxParams{params},
					})
				default:
					return store.ApplyScanBatch(ctx, db.ScanBatchParams{
						WalletID:     walletID,
						Transactions: []db.CreateTxParams{params},
					})
				}
			})
			waitTxGraphCall(t, ctx, store.DB(), result, 1)
			require.NoError(t, barrier.Commit(ctx))

			admissionErr := <-result

			// Assert: The public replay succeeds with exactly one intact
			// transaction; a blocked unique insert must not escape as an
			// error that would stall lnd's chain notification loop.
			require.NoError(t, admissionErr)

			stored, err := store.GetTx(ctx, db.GetTxQuery{
				WalletID: walletID,
				Txid:     hash,
			})
			require.NoError(t, err)
			require.Equal(t, db.TxStatusPending, stored.Status)
			require.Equal(t, raw.Bytes(), stored.SerializedTx)
			require.Equal(t, received, stored.Received)

			var count int

			err = store.DB().QueryRowContext(ctx, `
				SELECT count(*) FROM transactions
				WHERE wallet_id = $1 AND tx_hash = $2`,
				int64(walletID), hash[:],
			).Scan(&count)
			require.NoError(t, err)
			require.Equal(t, 1, count)
		})
	}
}

// TestUpdateTxConcurrentConfirmationPostgres verifies a row-local state patch
// cannot overwrite the result of a concurrent confirmed competing spend.
func TestUpdateTxConcurrentConfirmationPostgres(t *testing.T) {
	t.Parallel()

	// Arrange: Retain pending B and hold its row so confirming C can read the
	// branch but cannot yet replace B. Both calls share a bounded cancellation.
	store, childParams, winnerParams := newTxGraphConflict(t)
	walletID := childParams.WalletID
	rootHash := childParams.Tx.TxIn[0].PreviousOutPoint.Hash
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	barrier := lockTxGraphTransaction(t, ctx, store.DB(), walletID, rootHash)
	label := "racing update"

	// Act: Queue C at B, then ask UpdateTx to confirm B. Without graph ordering
	// its guard can pass before C commits and its later write revives B.
	winnerCall := startTxGraphCall(
		t, cancel, func() error {
			return store.CreateTx(ctx, winnerParams)
		},
	)
	waitTxGraphCall(t, ctx, store.DB(), winnerCall, 1)
	patchCall := startTxGraphCall(
		t, cancel, func() error {
			return store.UpdateTx(
				ctx, db.UpdateTxParams{
					WalletID: walletID, Txid: rootHash, Label: &label,
					State: &db.UpdateTxState{
						Block: winnerParams.Block, Status: db.TxStatusPublished,
					},
				},
			)
		},
	)
	waitTxGraphCall(t, ctx, store.DB(), patchCall, 2)
	require.NoError(t, barrier.Rollback())
	require.NoError(t, <-winnerCall)

	patchErr := <-patchCall

	// Assert: C remains the only confirmed claimant. B keeps its replaced
	// status and original label rather than accepting the stale metadata patch.
	require.ErrorIs(t, patchErr, db.ErrInvalidParam)
	root, err := store.GetTx(
		ctx, db.GetTxQuery{
			WalletID: walletID, Txid: rootHash,
		},
	)
	require.NoError(t, err)
	require.Equal(t, db.TxStatusReplaced, root.Status)
	require.Nil(t, root.Block)
	require.Empty(t, root.Label)

	winner, err := store.GetTx(
		ctx, db.GetTxQuery{
			WalletID: walletID, Txid: winnerParams.Tx.TxHash(),
		},
	)
	require.NoError(t, err)
	require.NotNil(t, winner.Block)
	require.Equal(t, db.TxStatusPublished, winner.Status)
}

// TestLeaseAcquisitionConcurrentConfirmationPostgres verifies an acquisition
// racing confirmation cannot resurrect a lease after the spend is disconnected.
func TestLeaseAcquisitionConcurrentConfirmationPostgres(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		set  bool
	}{
		{
			name: "single output",
		},
		{
			name: "output set",
			set:  true,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				// Arrange: Hold a funded credit after eligibility is read.
				// Both public routes use the same history and row barrier.
				store := NewTestStore(t)
				walletID, funding := newLeaseSetFixture(
					t, store, "lease-race", 1,
				)
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				t.Cleanup(cancel)

				barrier, err := store.DB().BeginTx(ctx, nil)
				require.NoError(t, err)
				t.Cleanup(func() { _ = barrier.Rollback() })

				_, err = barrier.ExecContext(
					ctx, `
				SELECT u.id FROM utxos AS u
				JOIN transactions AS t ON t.id = u.tx_id
				WHERE t.wallet_id = $1 AND t.tx_hash = $2
				AND u.output_index = $3 FOR UPDATE OF u
			`, walletID, funding[0].Hash[:], funding[0].Index,
				)
				require.NoError(t, err)

				spend := newRegularTx(
					funding, []*wire.TxOut{
						{Value: 5000, PkScript: []byte{0x51}},
					},
				)
				block := CreateBlockFixture(t, store.Queries(), 600)

				// Act: Start acquisition before confirmation. Release the
				// credit once recording commits or waits behind acquisition.
				leaseCall := startTxGraphCall(
					t, cancel, func() error {
						if test.set {
							_, err := store.LeaseOutputs(
								ctx, db.LeaseOutputsParams{
									WalletID: walletID, OutPoints: funding,
									ID: db.LockID{1}, NoExpiry: true,
								},
							)

							return err
						}

						_, err := store.LeaseOutput(
							ctx, db.LeaseOutputParams{
								WalletID: walletID, OutPoint: funding[0],
								ID: db.LockID{1}, NoExpiry: true,
							},
						)

						return err
					},
				)
				waitTxGraphCall(t, ctx, store.DB(), leaseCall, 1)
				confirmation := startTxGraphCall(
					t, cancel, func() error {
						return store.CreateTx(
							ctx, db.CreateTxParams{
								WalletID: walletID,
								Tx:       spend,
								Received: time.Unix(1, 0),
								Status:   db.TxStatusPublished, Block: &block,
							},
						)
					},
				)
				waitTxGraphCall(t, ctx, store.DB(), confirmation, 2)
				require.NoError(t, barrier.Rollback())
				require.NoError(t, <-leaseCall)
				require.NoError(t, <-confirmation)
				require.NoError(t, store.RollbackToBlock(ctx, block.Height))
				require.NoError(
					t, store.DeleteTx(
						ctx, db.DeleteTxParams{
							WalletID: walletID, Txid: spend.TxHash(),
						},
					),
				)

				// Assert: Both routes leave available funding without the
				// lease that confirmation already removed.
				require.True(
					t, walletUtxoExists(t, store, walletID, funding[0]),
				)
				require.Empty(t, leasedByID(t, store, walletID))
			},
		)
	}
}
