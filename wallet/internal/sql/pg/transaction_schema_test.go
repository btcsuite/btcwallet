//go:build test_db_postgres

package pg

import (
	"bytes"
	"context"
	"database/sql"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/stretchr/testify/require"
)

// testTransactionSchema verifies the transaction schema properties inherited
// from the legacy transaction store.
func testTransactionSchema(t *testing.T, db *sql.DB) {
	t.Helper()

	ctx := context.Background()
	_, err := db.ExecContext(ctx, `
		INSERT INTO wallets (
			id, wallet_name, manager_version, manager_created_at,
			is_watch_only, master_pub_params, encrypted_crypto_pub_key
		) VALUES (1, 'transactions-test', 1, 1, TRUE, $1, $2)
	`, []byte{1}, []byte{2})
	require.NoError(t, err)

	q := sqlc.New(db)
	for height := int32(100); height <= 101; height++ {
		require.NoError(t, q.InsertBlock(ctx, sqlc.InsertBlockParams{
			BlockHeight:    height,
			HeaderHash:     testHash(byte(height)),
			BlockTimestamp: 1000 + int64(height),
		}))
	}

	minedHash := testHash(1)
	var minedIDs []int64
	for i, height := range []int32{100, 101} {
		id, err := q.InsertTransaction(ctx, sqlc.InsertTransactionParams{
			WalletID:       1,
			TxHash:         minedHash,
			RawTx:          []byte{byte(i + 1)},
			ReceivedUnix:   2000,
			BlockHeight:    sql.NullInt32{Int32: height, Valid: true},
			ConfirmedOrder: sql.NullInt64{Int64: int64(i), Valid: true},
		})
		require.NoError(t, err)
		minedIDs = append(minedIDs, id)
	}
	incidences, err := q.ListTransactionIncidencesByHash(
		ctx, sqlc.ListTransactionIncidencesByHashParams{
			WalletID: 1,
			TxHash:   minedHash,
		},
	)
	require.NoError(t, err)
	require.Len(t, incidences, 2)

	var minedCreditIDs []int64
	for _, transactionID := range minedIDs {
		creditID, err := q.InsertCredit(ctx, sqlc.InsertCreditParams{
			WalletID: 1, TransactionID: transactionID, OutputIndex: 0,
			Amount: 5000, PkScript: []byte{0x51},
		})
		require.NoError(t, err)
		minedCreditIDs = append(minedCreditIDs, creditID)
	}
	require.NoError(t, q.SetActiveCreditIncidence(
		ctx, sqlc.SetActiveCreditIncidenceParams{
			WalletID: 1, ID: minedCreditIDs[1],
		},
	))
	unspent, err := q.ListUnspentCredits(
		ctx, sqlc.ListUnspentCreditsParams{WalletID: 1, NowUnix: 2000},
	)
	require.NoError(t, err)
	require.Len(t, unspent, 1)
	require.Equal(t, minedCreditIDs[1], unspent[0].ID)

	minedSpenderID, err := q.InsertTransaction(
		ctx, sqlc.InsertTransactionParams{
			WalletID: 1, TxHash: testHash(21), RawTx: []byte{21},
			ReceivedUnix:   2000,
			BlockHeight:    sql.NullInt32{Int32: 101, Valid: true},
			ConfirmedOrder: sql.NullInt64{Int64: 2, Valid: true},
		},
	)
	require.NoError(t, err)
	require.NoError(t, q.InsertTransactionInput(
		ctx, sqlc.InsertTransactionInputParams{
			SpendingTxID: minedSpenderID, InputIndex: 0,
			PrevTxHash: minedHash, PrevOutputIndex: 0,
		},
	))
	rows, err := q.RecordCreditSpend(ctx, sqlc.RecordCreditSpendParams{
		WalletID: 1, ID: minedCreditIDs[0],
		SpendingTxID: minedSpenderID, InputIndex: 0,
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
	firstCredits, err := q.ListTransactionCredits(
		ctx, sqlc.ListTransactionCreditsParams{
			WalletID: 1, TransactionID: minedIDs[0],
		},
	)
	require.NoError(t, err)
	require.True(t, firstCredits[0].IsSpent.Bool)
	secondCredits, err := q.ListTransactionCredits(
		ctx, sqlc.ListTransactionCreditsParams{
			WalletID: 1, TransactionID: minedIDs[1],
		},
	)
	require.NoError(t, err)
	require.False(t, secondCredits[0].IsSpent.Bool)
	unspent, err = q.ListUnspentCredits(
		ctx, sqlc.ListUnspentCreditsParams{WalletID: 1, NowUnix: 2000},
	)
	require.NoError(t, err)
	require.Len(t, unspent, 1)
	require.Equal(t, minedCreditIDs[1], unspent[0].ID)
	require.Error(t, q.DeleteBlock(ctx, 100))

	unminedHash := testHash(2)
	unminedID := insertUnminedTransaction(t, ctx, q, unminedHash)
	_, err = q.InsertTransaction(ctx, sqlc.InsertTransactionParams{
		WalletID: 1, TxHash: unminedHash, RawTx: []byte{9},
		ReceivedUnix: 2001,
	})
	require.Error(t, err)

	prevHash := testHash(3)
	for i := byte(0); i < 2; i++ {
		spenderID := insertUnminedTransaction(
			t, ctx, q, testHash(10+i),
		)
		require.NoError(t, q.InsertTransactionInput(
			ctx, sqlc.InsertTransactionInputParams{
				SpendingTxID: spenderID, InputIndex: 0,
				PrevTxHash: prevHash, PrevOutputIndex: 7,
			},
		))
	}
	spenders, err := q.ListUnminedSpenders(
		ctx, sqlc.ListUnminedSpendersParams{
			WalletID: 1, PrevTxHash: prevHash, PrevOutputIndex: 7,
		},
	)
	require.NoError(t, err)
	require.Len(t, spenders, 2)

	label := sqlc.PutTransactionLabelParams{
		WalletID: 1, TxHash: unminedHash, Label: []byte{0xff, 0x00, 0x01},
	}
	require.NoError(t, q.PutTransactionLabel(ctx, label))
	label.Label = []byte{0xfe, 0x02}
	require.NoError(t, q.PutTransactionLabel(ctx, label))
	rows, err = q.DeleteTransactionByID(
		ctx, sqlc.DeleteTransactionByIDParams{WalletID: 1, ID: unminedID},
	)
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
	gotLabel, err := q.GetTransactionLabel(
		ctx, sqlc.GetTransactionLabelParams{
			WalletID: 1, TxHash: unminedHash,
		},
	)
	require.NoError(t, err)
	require.Equal(t, label.Label, gotLabel)

	fundingID := insertUnminedTransaction(t, ctx, q, testHash(4))
	pkScript := []byte{0x51, 0x21, 0x02}
	fundingCreditID, err := q.InsertCredit(ctx, sqlc.InsertCreditParams{
		WalletID: 1, TransactionID: fundingID, OutputIndex: 0,
		Amount: 1234, PkScript: pkScript, IsChange: true,
	})
	require.NoError(t, err)
	require.NoError(t, q.SetActiveCreditIncidence(
		ctx, sqlc.SetActiveCreditIncidenceParams{
			WalletID: 1, ID: fundingCreditID,
		},
	))
	credit, err := q.GetCredit(ctx, sqlc.GetCreditParams{
		TransactionID: fundingID, OutputIndex: 0,
	})
	require.NoError(t, err)
	require.Equal(t, pkScript, credit.PkScript)
	require.True(t, credit.IsChange)
	require.False(t, credit.AddressScopeID.Valid)
	require.Nil(t, credit.AddressID)
	creditSpenderID := insertUnminedTransaction(t, ctx, q, testHash(20))
	require.NoError(t, q.InsertTransactionInput(
		ctx, sqlc.InsertTransactionInputParams{
			SpendingTxID: creditSpenderID, InputIndex: 0,
			PrevTxHash: testHash(4), PrevOutputIndex: 0,
		},
	))
	credits, err := q.ListTransactionCredits(
		ctx, sqlc.ListTransactionCreditsParams{
			WalletID: 1, TransactionID: fundingID,
		},
	)
	require.NoError(t, err)
	require.Len(t, credits, 1)
	require.True(t, credits[0].IsSpent.Bool)
	unspent, err = q.ListUnspentCredits(
		ctx, sqlc.ListUnspentCreditsParams{WalletID: 1, NowUnix: 2000},
	)
	require.NoError(t, err)
	for _, credit := range unspent {
		require.NotEqual(t, fundingCreditID, credit.ID)
	}

	leaseHash := testHash(5)
	lockID := testHash(6)
	rows, err = q.AcquireOutputLease(ctx, sqlc.AcquireOutputLeaseParams{
		WalletID: 1, TxHash: leaseHash, OutputIndex: 9,
		LockID: lockID, ExpiresUnix: 3000, NowUnix: 2000,
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
	rows, err = q.AcquireOutputLease(ctx, sqlc.AcquireOutputLeaseParams{
		WalletID: 1, TxHash: leaseHash, OutputIndex: 9,
		LockID: testHash(7), ExpiresUnix: 4000, NowUnix: 2000,
	})
	require.NoError(t, err)
	require.Zero(t, rows)
	rows, err = q.AcquireOutputLease(ctx, sqlc.AcquireOutputLeaseParams{
		WalletID: 1, TxHash: leaseHash, OutputIndex: 9,
		LockID: lockID, ExpiresUnix: 4000, NowUnix: 2000,
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
	rows, err = q.AcquireOutputLease(ctx, sqlc.AcquireOutputLeaseParams{
		WalletID: 1, TxHash: leaseHash, OutputIndex: 9,
		LockID: testHash(7), ExpiresUnix: 5000, NowUnix: 4000,
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, rows)
	lease, err := q.GetOutputLease(ctx, sqlc.GetOutputLeaseParams{
		WalletID: 1, TxHash: leaseHash, OutputIndex: 9,
	})
	require.NoError(t, err)
	require.Equal(t, testHash(7), lease.LockID)
}

// insertUnminedTransaction stores an unmined transaction fixture and returns
// its SQL identifier.
func insertUnminedTransaction(t *testing.T, ctx context.Context,
	q *sqlc.Queries, txHash []byte) int64 {

	t.Helper()

	id, err := q.InsertTransaction(ctx, sqlc.InsertTransactionParams{
		WalletID: 1, TxHash: txHash, RawTx: []byte{txHash[0]},
		ReceivedUnix: 2000,
	})
	require.NoError(t, err)

	return id
}

// testHash constructs a deterministic hash fixture from one byte.
func testHash(value byte) []byte {
	return bytes.Repeat([]byte{value}, 32)
}
