package sqlstore

import (
	"context"
	"database/sql"

	"github.com/btcsuite/btcwallet/waddrmgr"
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
	ID    int64
	Hash  []byte
	RawTx []byte
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
	BlockHash      []byte
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
	// PruneStaleSyncBlock removes the block at height once it has aged out of
	// the reorg-depth retention window, but only when no transaction or wallet
	// sync state still references it.
	PruneStaleSyncBlock(ctx context.Context, height int32) error
	// GetWalletStartBlock reads wallet start block from the transaction-bound
	// backend.
	GetWalletStartBlock(ctx context.Context, walletID int64) (BlockRow, error)
	// SetWalletSyncedTo updates wallet synced to through the transaction-bound
	// backend.
	SetWalletSyncedTo(ctx context.Context, walletID int64,
		blockHash []byte) (int64, error)
	// GetManagerState reads manager state from the transaction-bound backend.
	GetManagerState(ctx context.Context,
		walletID int64) (waddrmgr.ManagerState, error)
	// PutManagerState stores manager state through the transaction-bound
	// backend.
	PutManagerState(ctx context.Context, walletID int64,
		state waddrmgr.ManagerState) (int64, error)
	// GetSyncState reads sync state from the transaction-bound backend.
	GetSyncState(ctx context.Context,
		walletID int64) (waddrmgr.SyncState, error)
	// PutSyncState stores sync state through the transaction-bound backend.
	PutSyncState(ctx context.Context, walletID int64,
		state waddrmgr.SyncState) (int64, error)
	// SetWalletBirthday updates wallet birthday through the transaction-bound
	// backend.
	SetWalletBirthday(ctx context.Context, walletID,
		birthdayUnix int64) (int64, error)
	// SetWalletBirthdayBlock updates wallet birthday block through the
	// transaction-bound backend.
	SetWalletBirthdayBlock(ctx context.Context, walletID int64,
		blockHash []byte) (int64, error)
	// SetWalletBirthdayBlockVerified updates wallet birthday block verified
	// through the transaction-bound backend.
	SetWalletBirthdayBlockVerified(ctx context.Context, walletID int64,
		verified bool) (int64, error)
	// GetKeyScope reads key scope from the transaction-bound backend.
	GetKeyScope(ctx context.Context, walletID int64,
		scope waddrmgr.KeyScope) (waddrmgr.KeyScopeState, error)
	// ListKeyScopes reads key scopes from the transaction-bound backend in
	// stable order.
	ListKeyScopes(ctx context.Context,
		walletID int64) ([]waddrmgr.KeyScopeState, error)
	// PutKeyScope stores key scope through the transaction-bound backend.
	PutKeyScope(ctx context.Context, walletID int64,
		state waddrmgr.KeyScopeState) error
	// SetCoinTypeKeys updates coin type keys through the transaction-bound
	// backend.
	SetCoinTypeKeys(ctx context.Context, walletID int64,
		scope waddrmgr.KeyScope, encryptedPub,
		encryptedPriv []byte) (int64, error)
	// SetLastAccount updates last account through the transaction-bound
	// backend.
	SetLastAccount(ctx context.Context, walletID int64,
		scope waddrmgr.KeyScope, account uint32) (int64, error)
	// GetAccount reads account from the transaction-bound backend.
	GetAccount(ctx context.Context, walletID int64, scope waddrmgr.KeyScope,
		account uint32) (waddrmgr.AccountState, error)
	// GetAccountByName reads account by name from the transaction-bound
	// backend.
	GetAccountByName(ctx context.Context, walletID int64,
		scope waddrmgr.KeyScope, name string) (waddrmgr.AccountState, error)
	// ListAccounts reads accounts from the transaction-bound backend in stable
	// order.
	ListAccounts(ctx context.Context, walletID int64,
		scope waddrmgr.KeyScope) ([]waddrmgr.AccountState, error)
	// PutAccount stores account through the transaction-bound backend.
	PutAccount(ctx context.Context, walletID int64,
		state waddrmgr.AccountState) (int64, error)
	// RenameAccount updates one scoped account name.
	RenameAccount(ctx context.Context, walletID int64,
		scope waddrmgr.KeyScope, account uint32, name string) (int64, error)
	// SetAccountIndexes updates account indexes through the transaction-bound
	// backend.
	SetAccountIndexes(ctx context.Context, walletID int64,
		scope waddrmgr.KeyScope, account, nextExternal,
		nextInternal uint32) (int64, error)
	// GetAddress reads address from the transaction-bound backend.
	GetAddress(ctx context.Context, walletID int64, scope waddrmgr.KeyScope,
		hash []byte) (waddrmgr.AddressState, error)
	// ListAccountAddresses reads account addresses from the transaction-bound
	// backend in stable order.
	ListAccountAddresses(ctx context.Context, walletID int64,
		scope waddrmgr.KeyScope, account uint32) ([]waddrmgr.AddressState,
		error)
	// ListActiveAddresses reads active addresses from the transaction-bound
	// backend in stable order.
	ListActiveAddresses(ctx context.Context, walletID int64,
		scope waddrmgr.KeyScope) ([]waddrmgr.AddressState, error)
	// PutAddress stores address through the transaction-bound backend.
	PutAddress(ctx context.Context, walletID int64,
		state waddrmgr.AddressState) (int64, error)
	// MarkAddressUsed marks address used in the transaction-bound backend.
	MarkAddressUsed(ctx context.Context, walletID int64,
		scope waddrmgr.KeyScope, hash []byte) (int64, error)
	// DeletePrivateKeys removes private keys through the transaction-bound
	// backend.
	DeletePrivateKeys(ctx context.Context, walletID int64) error

	// GetTransactionDetailsByHash reads transaction details by hash from the
	// transaction-bound backend.
	GetTransactionDetailsByHash(ctx context.Context, walletID int64,
		hash []byte) (TransactionDetailsRow, error)
	// GetUnminedTransactionDetails reads unmined transaction details from the
	// transaction-bound backend.
	GetUnminedTransactionDetails(ctx context.Context, walletID int64,
		hash []byte) (TransactionDetailsRow, error)
	// GetMinedTransactionDetails reads mined transaction details from the
	// transaction-bound backend.
	GetMinedTransactionDetails(ctx context.Context, walletID int64,
		hash []byte, height int32, blockHash []byte) (
		TransactionDetailsRow, error)
	// GetTransactionDetailsByID reads transaction details by id from the
	// transaction-bound backend.
	GetTransactionDetailsByID(ctx context.Context, walletID,
		transactionID int64) (TransactionDetailsRow, error)
	// ListTransactionDetailCredits reads transaction detail credits from the
	// transaction-bound backend in stable order.
	ListTransactionDetailCredits(ctx context.Context, walletID,
		transactionID int64) ([]TransactionCreditRow, error)
	// ListTransactionDebits reads transaction debits from the transaction-bound
	// backend in stable order.
	ListTransactionDebits(ctx context.Context, walletID,
		transactionID int64) ([]TransactionDebitRow, error)
	// GetTransactionLabel reads transaction label from the transaction-bound
	// backend.
	GetTransactionLabel(ctx context.Context, walletID int64,
		hash []byte) ([]byte, error)
	// ListUnminedTransactions reads unmined transactions from the
	// transaction-bound backend in stable order.
	ListUnminedTransactions(ctx context.Context,
		walletID int64) ([]TransactionRow, error)
	// ListMinedTransactionsForward reads mined transactions forward from the
	// transaction-bound backend in stable order.
	ListMinedTransactionsForward(ctx context.Context, walletID int64,
		startHeight, endHeight int32) ([]TransactionIncidenceRow, error)
	// ListMinedTransactionsReverse reads mined transactions reverse from the
	// transaction-bound backend in stable order.
	ListMinedTransactionsReverse(ctx context.Context, walletID int64,
		startHeight, endHeight int32) ([]TransactionIncidenceRow, error)
	// ListUnspentCredits reads unspent credits from the transaction-bound
	// backend in stable order.
	ListUnspentCredits(ctx context.Context, walletID,
		nowUnix int64) ([]CreditRow, error)
	// ListOutputsToWatch reads outputs to watch from the transaction-bound
	// backend in stable order.
	ListOutputsToWatch(ctx context.Context,
		walletID int64) ([]CreditRow, error)
	// GetMinedTransactionID reads mined transaction id from the
	// transaction-bound backend.
	GetMinedTransactionID(ctx context.Context, walletID int64,
		hash []byte, height int32, blockHash []byte) (int64, error)
	// GetUnminedPreviousPkScript reads unmined previous pk script from the
	// transaction-bound backend.
	GetUnminedPreviousPkScript(ctx context.Context, walletID int64,
		hash []byte, index uint32) ([]byte, error)
	// GetMinedPreviousPkScript reads mined previous pk script from the
	// transaction-bound backend.
	GetMinedPreviousPkScript(ctx context.Context, walletID,
		transactionID int64, inputIndex uint32) ([]byte, error)

	// GetUnminedTransactionID reads unmined transaction id from the
	// transaction-bound backend.
	GetUnminedTransactionID(ctx context.Context, walletID int64,
		hash []byte) (int64, error)
	// NextBlockTransactionOrder returns next block transaction order from the
	// transaction-bound backend.
	NextBlockTransactionOrder(ctx context.Context, walletID int64,
		blockHash []byte) (int64, error)
	// InsertTransaction records transaction through the transaction-bound
	// backend.
	InsertTransaction(ctx context.Context,
		params InsertTransactionParams) (int64, error)
	// PromoteUnminedTransaction promotes unmined transaction in the
	// transaction-bound backend.
	PromoteUnminedTransaction(ctx context.Context, walletID int64,
		hash, blockHash []byte, order int64) (int64, error)
	// InsertTransactionInput records transaction input through the
	// transaction-bound backend.
	InsertTransactionInput(ctx context.Context, transactionID int64,
		inputIndex uint32, prevHash []byte, prevIndex uint32) error
	// ListUnminedSpenders reads unmined spenders from the transaction-bound
	// backend in stable order.
	ListUnminedSpenders(ctx context.Context, walletID int64,
		prevHash []byte, prevIndex uint32,
		excludeTransactionID int64) ([]UnminedSpenderRow, error)
	// GetActiveCreditID reads active credit id from the transaction-bound
	// backend.
	GetActiveCreditID(ctx context.Context, walletID int64,
		hash []byte, index uint32) (int64, error)
	// RecordCreditSpend records credit spend in the transaction-bound backend.
	RecordCreditSpend(ctx context.Context, walletID, creditID,
		transactionID int64, inputIndex uint32) (int64, error)
	// DeleteOutputLeaseAnyOwner removes output lease any owner through the
	// transaction-bound backend.
	DeleteOutputLeaseAnyOwner(ctx context.Context, walletID int64,
		hash []byte, index uint32) (int64, error)
	// GetCreditID reads credit id from the transaction-bound backend.
	GetCreditID(ctx context.Context, transactionID int64,
		index uint32) (int64, error)
	// InsertCredit records credit through the transaction-bound backend.
	InsertCredit(ctx context.Context, walletID, transactionID int64,
		index uint32, amount int64, pkScript []byte,
		change bool) (int64, error)
	// PutTransactionLabel stores transaction label through the
	// transaction-bound backend.
	PutTransactionLabel(ctx context.Context, walletID int64,
		hash, label []byte) error
	// IsKnownOutput reports whether known output is present in the
	// transaction-bound backend.
	IsKnownOutput(ctx context.Context, walletID int64, hash []byte,
		index uint32) (bool, error)
	// AcquireOutputLease acquires output lease in the transaction-bound
	// backend.
	AcquireOutputLease(ctx context.Context, walletID int64, hash []byte,
		index uint32, lockID []byte, expiresUnix,
		nowUnix int64) (int64, error)
	// GetOutputLease reads output lease from the transaction-bound backend.
	GetOutputLease(ctx context.Context, walletID int64, hash []byte,
		index uint32) (OutputLeaseRow, error)
	// DeleteOutputLease removes output lease through the transaction-bound
	// backend.
	DeleteOutputLease(ctx context.Context, walletID int64, hash []byte,
		index uint32, lockID []byte) (int64, error)
	// DeleteExpiredOutputLeases removes expired output leases through the
	// transaction-bound backend.
	DeleteExpiredOutputLeases(ctx context.Context, walletID,
		nowUnix int64) (int64, error)
	// ListActiveOutputLeases reads active output leases from the
	// transaction-bound backend in stable order.
	ListActiveOutputLeases(ctx context.Context, walletID,
		nowUnix int64) ([]OutputLeaseRow, error)

	// ListMinedTransactionsFromHeight reads mined transactions from height from
	// the transaction-bound backend in stable order.
	ListMinedTransactionsFromHeight(ctx context.Context, walletID int64,
		height int32) ([]MinedTransactionRow, error)
	// DeleteCreditSpendsBySpendingTx removes credit spends by spending tx
	// through the transaction-bound backend.
	DeleteCreditSpendsBySpendingTx(ctx context.Context, walletID,
		transactionID int64) (int64, error)
	// DetachMinedTransaction detaches mined transaction in the
	// transaction-bound backend.
	DetachMinedTransaction(ctx context.Context, walletID,
		transactionID int64) (int64, error)
	// ListTransactionCreditIDs reads transaction credit ids from the
	// transaction-bound backend in stable order.
	ListTransactionCreditIDs(ctx context.Context, walletID,
		transactionID int64) ([]int64, error)
	// SetActiveCreditIncidence updates active credit incidence through the
	// transaction-bound backend.
	SetActiveCreditIncidence(ctx context.Context, walletID,
		creditID int64) error
	// ListUnminedSpendersByPrevHash reads unmined spenders by prev hash from
	// the transaction-bound backend in stable order.
	ListUnminedSpendersByPrevHash(ctx context.Context, walletID int64,
		hash []byte) ([]UnminedSpenderRow, error)
	// DeleteTransaction removes transaction through the transaction-bound
	// backend.
	DeleteTransaction(ctx context.Context, walletID,
		transactionID int64) (int64, error)
}
