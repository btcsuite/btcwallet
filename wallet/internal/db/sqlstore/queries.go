package sqlstore

import (
	"context"
	"database/sql"
)

// BlockRow is the backend-neutral representation of a blocks table row.
type BlockRow struct {
	Height    int32
	Hash      []byte
	Timestamp int64
}

// TransactionDetailsRow contains the generated columns used to reconstruct a
// wtxmgr transaction detail.
type TransactionDetailsRow struct {
	ID             int64
	RawTx          []byte
	Received       int64
	BlockHeight    sql.NullInt64
	ConfirmedOrder sql.NullInt64
	BlockHash      []byte
	BlockTimestamp sql.NullInt64
	Label          []byte
}

// TransactionRow contains one transaction incidence.
type TransactionRow struct {
	ID          int64
	Hash        []byte
	RawTx       []byte
	BlockHeight sql.NullInt64
}

// TransactionIncidenceRow identifies one mined transaction incidence.
type TransactionIncidenceRow struct {
	ID     int64
	Height int32
}

// TransactionCreditRow contains one credit attached to a transaction detail.
type TransactionCreditRow struct {
	OutputIndex int64
	Amount      int64
	IsChange    bool
	IsSpent     bool
}

// TransactionDebitRow contains one debit attached to a transaction detail.
type TransactionDebitRow struct {
	InputIndex int64
	Amount     int64
}

// CreditRow contains the generated columns used by the wtxmgr credit views.
type CreditRow struct {
	Hash           []byte
	OutputIndex    int64
	Amount         int64
	PkScript       []byte
	Received       int64
	BlockHeight    sql.NullInt64
	IsCoinbase     bool
	BlockHash      []byte
	BlockTimestamp sql.NullInt64
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

// OutputLeaseRow contains one persisted output lease.
type OutputLeaseRow struct {
	Hash       []byte
	Index      int64
	LockID     []byte
	Expiration int64
}

// InsertTransactionParams contains a transaction incidence to persist.
type InsertTransactionParams struct {
	WalletID       int64
	Hash           []byte
	RawTx          []byte
	Received       int64
	BlockHeight    sql.NullInt64
	ConfirmedOrder sql.NullInt64
	IsCoinbase     bool
}

// Queries is the sqlc-generated query subset required by the manager store.
// Backend adapters normalize SQLite and PostgreSQL integer widths here.
//
//nolint:interfacebloat // One SQL transaction binds both manager domains.
type Queries interface {
	// PutBlock stores block through the transaction-bound backend.
	PutBlock(ctx context.Context, row BlockRow) error
	// GetBlockByHeight reads block by height from the transaction-bound
	// backend.
	GetBlockByHeight(ctx context.Context, height int32) (BlockRow, error)
	// GetWalletStartBlock reads wallet start block from the transaction-bound
	// backend.
	GetWalletStartBlock(ctx context.Context, walletID int64) (BlockRow, error)
	// SetWalletSyncedTo updates wallet synced to through the transaction-bound
	// backend.
	SetWalletSyncedTo(ctx context.Context, walletID int64,
		height int32) (int64, error)

	GetTransactionDetailsByHash(ctx context.Context, walletID int64,
		hash []byte) (TransactionDetailsRow, error)
	GetUnminedTransactionDetails(ctx context.Context, walletID int64,
		hash []byte) (TransactionDetailsRow, error)
	GetMinedTransactionDetails(ctx context.Context, walletID int64,
		hash []byte, height int32, blockHash []byte) (
		TransactionDetailsRow, error)
	GetTransactionDetailsByID(ctx context.Context, walletID,
		transactionID int64) (TransactionDetailsRow, error)
	ListTransactionDetailCredits(ctx context.Context, walletID,
		transactionID int64) ([]TransactionCreditRow, error)
	ListTransactionDebits(ctx context.Context, walletID,
		transactionID int64) ([]TransactionDebitRow, error)
	GetTransactionLabel(ctx context.Context, walletID int64,
		hash []byte) ([]byte, error)
	ListUnminedTransactions(ctx context.Context,
		walletID int64) ([]TransactionRow, error)
	ListMinedTransactionsForward(ctx context.Context, walletID int64,
		startHeight, endHeight int32) ([]TransactionIncidenceRow, error)
	ListMinedTransactionsReverse(ctx context.Context, walletID int64,
		startHeight, endHeight int32) ([]TransactionIncidenceRow, error)
	ListUnspentCredits(ctx context.Context, walletID,
		nowUnix int64) ([]CreditRow, error)
	ListOutputsToWatch(ctx context.Context,
		walletID int64) ([]CreditRow, error)
	GetMinedTransactionID(ctx context.Context, walletID int64,
		hash []byte, height int32, blockHash []byte) (int64, error)
	GetUnminedPreviousPkScript(ctx context.Context, walletID int64,
		hash []byte, index uint32) ([]byte, error)
	GetMinedPreviousPkScript(ctx context.Context, walletID,
		transactionID int64, inputIndex uint32) ([]byte, error)

	GetUnminedTransactionID(ctx context.Context, walletID int64,
		hash []byte) (int64, error)
	NextBlockTransactionOrder(ctx context.Context, walletID int64,
		height int32) (int64, error)
	InsertTransaction(ctx context.Context,
		params InsertTransactionParams) (int64, error)
	PromoteUnminedTransaction(ctx context.Context, walletID int64,
		hash []byte, height int32, order int64) (int64, error)
	InsertTransactionInput(ctx context.Context, transactionID int64,
		inputIndex uint32, prevHash []byte, prevIndex uint32) error
	ListUnminedSpenders(ctx context.Context, walletID int64,
		prevHash []byte, prevIndex uint32,
		excludeTransactionID int64) ([]UnminedSpenderRow, error)
	GetActiveCreditID(ctx context.Context, walletID int64,
		hash []byte, index uint32) (int64, error)
	RecordCreditSpend(ctx context.Context, walletID, creditID,
		transactionID int64, inputIndex uint32) (int64, error)
	DeleteOutputLeaseAnyOwner(ctx context.Context, walletID int64,
		hash []byte, index uint32) (int64, error)
	GetCreditID(ctx context.Context, transactionID int64,
		index uint32) (int64, error)
	InsertCredit(ctx context.Context, walletID, transactionID int64,
		index uint32, amount int64, pkScript []byte,
		change bool) (int64, error)
	PutTransactionLabel(ctx context.Context, walletID int64,
		hash, label []byte) error
	IsKnownOutput(ctx context.Context, walletID int64, hash []byte,
		index uint32) (bool, error)
	AcquireOutputLease(ctx context.Context, walletID int64, hash []byte,
		index uint32, lockID []byte, expiresUnix,
		nowUnix int64) (int64, error)
	GetOutputLease(ctx context.Context, walletID int64, hash []byte,
		index uint32) (OutputLeaseRow, error)
	DeleteOutputLease(ctx context.Context, walletID int64, hash []byte,
		index uint32, lockID []byte) (int64, error)
	DeleteExpiredOutputLeases(ctx context.Context, walletID,
		nowUnix int64) (int64, error)
	ListActiveOutputLeases(ctx context.Context, walletID,
		nowUnix int64) ([]OutputLeaseRow, error)

	ListMinedTransactionsFromHeight(ctx context.Context, walletID int64,
		height int32) ([]MinedTransactionRow, error)
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
