package sqlstore

import "context"

// BlockRow is the backend-neutral representation of a blocks table row.
type BlockRow struct {
	Height    int32
	Hash      []byte
	Timestamp int64
}

// MinedTransactionRow identifies a mined transaction being disconnected.
type MinedTransactionRow struct {
	ID         int64
	Hash       []byte
	IsCoinbase bool
}

// UnminedSpenderRow identifies an unmined transaction that spends a hash.
type UnminedSpenderRow struct {
	ID   int64
	Hash []byte
}

// Queries is the generated-query subset required by the manager transaction
// store. Backend adapters normalize SQLite and PostgreSQL integer widths here.
//
//nolint:interfacebloat // One SQL transaction binds both manager domains.
type Queries interface {
	PutBlock(ctx context.Context, row BlockRow) error
	GetBlockByHeight(ctx context.Context, height int32) (BlockRow, error)
	GetWalletStartBlock(ctx context.Context, walletID int64) (BlockRow, error)
	SetWalletSyncedTo(ctx context.Context, walletID int64,
		height int32) (int64, error)

	ListMinedTransactionsFromHeight(ctx context.Context, walletID int64,
		height int32) ([]MinedTransactionRow, error)
	GetUnminedTransactionID(ctx context.Context, walletID int64,
		hash []byte) (int64, error)
	DeleteCreditSpendsBySpendingTx(ctx context.Context, walletID,
		transactionID int64) (int64, error)
	DetachMinedTransaction(ctx context.Context, walletID,
		transactionID int64) (int64, error)
	ListTransactionCreditIDs(ctx context.Context, walletID,
		transactionID int64) ([]int64, error)
	SetActiveCreditIncidence(ctx context.Context, walletID,
		creditID int64) error
	ListUnminedSpendersByPrevHash(ctx context.Context, walletID int64,
		hash []byte) ([]UnminedSpenderRow, error)
	DeleteTransaction(ctx context.Context, walletID,
		transactionID int64) (int64, error)
}
