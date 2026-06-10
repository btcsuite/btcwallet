package db

import (
	"context"
	"errors"
	"iter"

	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
)

var (
	// ErrWalletNotFound is returned when a wallet is not found in the
	// database.
	ErrWalletNotFound = errors.New("wallet not found")

	// ErrAddressTypeNotFound is returned when an address type is not found.
	ErrAddressTypeNotFound = errors.New("address type not found")

	// ErrSecretNotFound is returned when a secret is not found or is empty
	// in the database.
	ErrSecretNotFound = errors.New("secret not found")

	// ErrWatchOnlyViolation is returned when an operation violates watch-only
	// invariants. Watch-only means the wallet or address lacks private key
	// material and cannot sign transactions.
	ErrWatchOnlyViolation = errors.New("watch-only invariant violation")

	// ErrSpendableWalletNeedsAccountPrivKey is returned when a non-watch-only
	// wallet receives an imported account whose payload omits the encrypted
	// account private key. Spendable wallets must hold matching key material
	// for every imported account; the symmetric counterpart of
	// ErrWatchOnlyViolation.
	ErrSpendableWalletNeedsAccountPrivKey = errors.New(
		"spendable wallet must not contain an imported account without " +
			"private-key material",
	)

	// ErrSpendableWalletNeedsAddressPrivKey is returned when a non-watch-only
	// wallet receives an imported address whose payload omits the encrypted
	// address private key. Symmetric counterpart of ErrWatchOnlyViolation for
	// the address surface; covers public-only AND script-only imports.
	ErrSpendableWalletNeedsAddressPrivKey = errors.New(
		"spendable wallet must not contain an imported address without " +
			"private-key material",
	)

	// ErrNilDB is returned when a nil database connection pointer is
	// provided to the wallet.
	ErrNilDB = errors.New("wallet requires a non-nil database connection")

	// ErrAccountNotFound is returned when an account is not found in the
	// database.
	ErrAccountNotFound = errors.New("account not found")

	// ErrAddressNotFound is returned when an address is not found in the
	// database.
	ErrAddressNotFound = errors.New("address not found")

	// ErrKeyScopeNotFound is returned when a key scope is not found in the
	// database.
	ErrKeyScopeNotFound = errors.New("key scope not found")

	// ErrUnknownKeyScope is returned when a key scope is not found in
	// ScopeAddrMap.
	ErrUnknownKeyScope = errors.New("unknown scope in ScopeAddrMap")

	// ErrInvalidAccountQuery is returned when both or neither account filters
	// are provided in GetAccount or RenameAccount.
	ErrInvalidAccountQuery = errors.New(
		"exactly one of Name or AccountNumber must be provided",
	)

	// ErrInvalidAddressQuery is returned when GetAddressQuery has invalid
	// field combinations.
	ErrInvalidAddressQuery = errors.New("ScriptPubKey must be provided")

	// ErrInvalidPageLimit is returned when a paginated query is called with a
	// zero page limit.
	ErrInvalidPageLimit = page.ErrInvalidLimit

	// ErrMissingScriptPubKey is returned when creating an imported
	// address without the required script public key.
	ErrMissingScriptPubKey = errors.New("script pubkey required")

	// ErrMissingAccountPublicKey is returned when an imported account is
	// missing the public key.
	ErrMissingAccountPublicKey = errors.New(
		"imported account requires a public key",
	)

	// ErrMissingAccountName is returned when an account is being created
	// without a name.
	ErrMissingAccountName = errors.New("account name is required")

	// ErrReservedAccountName is returned when a caller-initiated account
	// operation targets the reserved wallet-level imported bucket name
	// (DefaultImportedAccountName). Raw single imports use that alias in
	// compatibility responses and filters, but SQL must not materialize it as
	// an account row; neither derived, imported-xpub, nor rename public APIs
	// may occupy it.
	ErrReservedAccountName = errors.New(
		"account name is reserved for the imported bucket",
	)

	// ErrMaxAccountNumberReached indicates that no more accounts can be created
	// within a key scope because the account number counter has reached its
	// maximum representable value.
	ErrMaxAccountNumberReached = errors.New("max account number reached")

	// ErrMaxAddressIndexReached indicates that no more addresses can be
	// created within a branch because the address index counter has reached
	// its maximum representable value.
	ErrMaxAddressIndexReached = errors.New("max address index reached")

	// ErrTxNotFound is returned when a transaction is not found in the
	// database.
	ErrTxNotFound = errors.New("tx not found")

	// ErrTxAlreadyExists is returned when CreateTx is asked to insert a
	// wallet-scoped transaction hash that already exists.
	ErrTxAlreadyExists = errors.New("tx already exists")

	// ErrBlockNotFound is returned when a transaction operation references a
	// block height that does not exist in the shared blocks table.
	ErrBlockNotFound = errors.New("block not found")

	// ErrBlockMismatch is returned when a transaction operation references a
	// block height whose stored hash or timestamp does not match the supplied
	// block metadata.
	ErrBlockMismatch = errors.New("block metadata mismatch")

	// ErrUtxoNotFound is returned when a UTXO is not found in the database.
	ErrUtxoNotFound = errors.New("utxo not found")

	// ErrTxInputConflict is returned when CreateTx references a wallet-owned
	// input that is already claimed by another recorded wallet spend.
	ErrTxInputConflict = errors.New(
		"transaction input conflicts with another wallet spend",
	)

	// ErrTxInputInvalidParent is returned when CreateTx references a wallet-
	// owned input whose parent transaction is already invalid.
	ErrTxInputInvalidParent = errors.New(
		"transaction input spends wallet output with invalid parent",
	)
)

// Store defines the set of database operations used by the wallet.
//
// NOTE: Ideally each wallet component/manager should depend on a small,
// purpose-built interface (for example, the UtxoManager should only depend on
// UTXOStore). However, the wallet is still a monolithic struct and its managers
// are currently only separated by files, all implemented as methods on Wallet.
// Until we break the wallet into independent components, we use this monolithic
// Store abstraction as a transitional step.
//
// For this PR, Store includes wallet, account, address, UTXO, and tx store
// interfaces.
//
// TODO(yy): Break down wallet managers into independent components.
type Store interface {
	WalletStore
	AccountStore
	AddressStore
	UTXOStore
	TxStore

	// StatsSnapshot returns the current runtime counters tracked by the
	// backend.
	// Backends without SQL classification support may return an empty snapshot.
	StatsSnapshot() dbruntime.StatsSnapshot
}

// WalletStore defines the methods for wallet-level operations.
type WalletStore interface {
	// CreateWallet creates a new wallet in the database with the provided
	// parameters. It returns the ID of the newly created wallet or an error
	// if the creation fails.
	CreateWallet(ctx context.Context, params CreateWalletParams) (
		*WalletInfo, error)

	// GetWallet retrieves information about a wallet given its name. SQL
	// multi-wallet backends return ErrWalletNotFound when the wallet name is
	// unknown. The legacy kvdb backend is a single-wallet adapter and echoes
	// the requested name without validating it.
	GetWallet(ctx context.Context, name string) (*WalletInfo, error)

	// ListWallets returns one page of wallets for the given query, including a
	// next-cursor for the following page.
	ListWallets(ctx context.Context, query ListWalletsQuery) (
		page.Result[WalletInfo, uint32], error)

	// IterWallets returns an iterator that fetches pages transparently and
	// yields wallets one by one until exhaustion or error.
	IterWallets(ctx context.Context,
		query ListWalletsQuery) iter.Seq2[WalletInfo, error]

	// ListSyncedBlocks returns the wallet's synced block metadata for the
	// requested inclusive height range.
	ListSyncedBlocks(ctx context.Context,
		query ListSyncedBlocksQuery) ([]Block, error)

	// UpdateWallet updates various properties of a wallet, such as its
	// birthday, birthday block, or sync state. SQL multi-wallet backends
	// return ErrWalletNotFound when the wallet ID is unknown. The legacy kvdb
	// backend is a single-wallet adapter and ignores WalletID.
	UpdateWallet(ctx context.Context, params UpdateWalletParams) error

	// GetEncryptedHDSeed retrieves the encrypted Hierarchical
	// Deterministic (HD) seed (the encrypted master HD private key) of
	// the wallet. This seed is sensitive information and is returned in
	// its encrypted form. It returns the encrypted seed as a byte slice
	// or an error if the retrieval fails.
	GetEncryptedHDSeed(ctx context.Context, walletID uint32) ([]byte, error)

	// GetWalletSecrets retrieves the encrypted wallet secret material for the
	// given wallet. Watch-only wallets may return empty secret fields without
	// error when those values are absent in storage. If the wallet exists but
	// its wallet_secrets row is missing, it returns ErrSecretNotFound rather
	// than ErrWalletNotFound.
	GetWalletSecrets(ctx context.Context, walletID uint32) (*WalletSecrets,
		error)

	// UpdateWalletSecrets updates the secrets for the wallet.
	UpdateWalletSecrets(ctx context.Context,
		params UpdateWalletSecretsParams) error
}

// AccountStore defines the database actions for managing accounts.
type AccountStore interface {
	// CreateDerivedAccount creates a new derived account with the given
	// name and scope. After allocating the account number, the store
	// invokes deriveFn to obtain the wallet-derived account material
	// and persists it with the row.
	//
	// If the key scope does not exist, it will be automatically created
	// using the address schema from ScopeAddrMap with no coin public/private
	// key material. Spendable scopes may later gain a key_scope_secrets row;
	// watch-only scopes remain absent from that table.
	CreateDerivedAccount(ctx context.Context,
		params CreateDerivedAccountParams,
		deriveFn AccountDerivationFunc) (*AccountInfo, error)

	// CreateImportedAccount stores an imported account identified by
	// an extended public key. Returns the persisted account as an
	// AccountInfo populated with the durable fields the wallet
	// expects (PublicKey, MasterKeyFingerprint, etc.).
	//
	// If the key scope does not exist, it will be automatically created
	// using the address schema from ScopeAddrMap with no coin public/private
	// key material. Spendable scopes may later gain a key_scope_secrets row;
	// watch-only scopes remain absent from that table.
	CreateImportedAccount(ctx context.Context,
		params CreateImportedAccountParams) (*AccountInfo, error)

	// GetAccount retrieves information about a specific account,
	// identified by its name or account number within a given key scope.
	// It returns an AccountInfo struct containing the account's properties
	// or an error if the account is not found.
	GetAccount(ctx context.Context, query GetAccountQuery) (
		*AccountInfo, error)

	// GetAccountSecret retrieves encrypted account-level signing material for
	// one account. The result contains encrypted material only; callers must
	// use the wallet key vault to decrypt it.
	GetAccountSecret(ctx context.Context, query GetAccountSecretQuery) (
		*AccountSecret, error)

	// ListAccounts returns a slice of AccountInfo for all accounts,
	// optionally filtered by name or key scope. It returns an empty slice
	// if no accounts are found.
	ListAccounts(ctx context.Context, query ListAccountsQuery) (
		[]AccountInfo, error)

	// RenameAccount changes the name of an account. The account can be
	// identified by its old name or its account number. It returns an
	// error if the renaming fails.
	RenameAccount(ctx context.Context, params RenameAccountParams) error
}

// AddressDerivationFunc derives address data after a SQL backend allocates an
// address index. The callback receives a value struct so new derivation inputs
// can be added without changing every call site again.
type AddressDerivationFunc func(ctx context.Context,
	params AddressDerivationParams) (*DerivedAddressData, error)

// AccountDerivationFunc is invoked by the database layer after allocating a
// derived account number to obtain the wallet-derived account material. The
// db layer does not perform crypto.
//
// The callback runs with the wallet watch-only mode the workflow loaded via
// ops.WalletWatchOnly. It MUST NOT call db.Store methods or open a walletdb
// transaction: the store is already inside a write tx and nested access can
// deadlock (SQLite) or break tx semantics.
type AccountDerivationFunc func(ctx context.Context, scope KeyScope,
	accountNumber uint32,
	walletIsWatchOnly bool) (*DerivedAccountData, error)

// DerivedAccountData carries the wallet-derived account material persisted
// alongside an allocated derived account number.
//
// Validation rules enforced by CreateDerivedAccountWithOps:
//   - PublicKey must be non-empty.
//   - EncryptedPrivateKey may be nil only if walletIsWatchOnly is true.
type DerivedAccountData struct {
	// PublicKey is the plaintext account-level extended public key.
	PublicKey []byte

	// EncryptedPrivateKey is the encrypted account-level extended private
	// key. Nil only when the wallet is watch-only.
	EncryptedPrivateKey []byte

	// MasterKeyFingerprint is the fingerprint of the root master key
	// (BIP32 m/) corresponding to PublicKey.
	MasterKeyFingerprint uint32
}

// AddressStore defines the database actions for managing addresses.
type AddressStore interface {
	// NewDerivedAddress creates a new HD-derived address for the specified
	// account and key scope. The concrete backend owns address derivation:
	// SQL backends use their configured AddressDerivationFunc, while kvdb
	// preserves legacy waddrmgr derivation semantics.
	NewDerivedAddress(ctx context.Context,
		params NewDerivedAddressParams) (*AddressInfo, error)

	// NewImportedAddress imports a new address, script, or private key.
	// If a private key is provided in the parameters, the address will
	// be spendable. Otherwise, it will be imported as watch-only. It
	// returns information about the imported address or an error if the
	// import fails.
	NewImportedAddress(ctx context.Context,
		params NewImportedAddressParams) (*AddressInfo, error)

	// GetAddress retrieves information about a specific address. It
	// returns an AddressInfo struct containing the address's properties or
	// an error if the address is not found.
	GetAddress(ctx context.Context, query GetAddressQuery) (*AddressInfo, error)

	// ResolveOwnedAddresses resolves a batch of script pubkeys to the subset
	// that is owned by the wallet in a single store operation. It is intended
	// to replace a per-script GetAddress loop on hot paths such as transaction-
	// output ownership filtering.
	//
	// The result is keyed by string(ScriptPubKey). Only wallet-owned scripts
	// appear in the map: a script absent from the result is simply not owned
	// by the wallet (the batched equivalent of GetAddress returning
	// ErrAddressNotFound), which is not an error. Both the wallet ID and the
	// supplied script set constrain the lookup.
	//
	// An empty or nil ScriptPubKeys slice returns an empty, non-nil map
	// without issuing a backend query or returning an error.
	ResolveOwnedAddresses(ctx context.Context,
		query ResolveOwnedAddressesQuery) (
		map[string]*AddressInfo, error)

	// ListAddresses returns one page of addresses for the given query,
	// including a next-cursor for the following page.
	ListAddresses(ctx context.Context, query ListAddressesQuery) (
		page.Result[AddressInfo, uint32], error)

	// IterAddresses returns an iterator that fetches pages transparently and
	// yields addresses one by one until exhaustion or error.
	IterAddresses(ctx context.Context,
		query ListAddressesQuery) iter.Seq2[AddressInfo, error]

	// GetAddressSecret retrieves the encrypted secret material for a given
	// address. Returns the AddressSecret containing encrypted private key
	// and scripts, or an error if the secret does not exist.
	GetAddressSecret(ctx context.Context,
		query GetAddressSecretQuery) (*AddressSecret, error)

	// ListAddressTypes returns all supported address types along with their
	// readable descriptions, wrapped in AddressTypeInfo values.
	ListAddressTypes(ctx context.Context) ([]AddressTypeInfo, error)

	// GetAddressType returns the AddressTypeInfo associated with the given
	// address type identifier. An error is returned if the type is unknown.
	GetAddressType(ctx context.Context, id AddressType) (AddressTypeInfo, error)
}

// TxStore defines the database actions for managing transaction records.
//
//nolint:interfacebloat // Transitional tx migration keeps routes grouped.
type TxStore interface {
	// CreateTx atomically records a transaction row and its associated credits
	// in the database. This Store-layer API persists already-constructed
	// wallet history; it does not build or publish transactions on the
	// caller's behalf.
	//
	// The same write also updates the corresponding UTXO state: it marks any
	// wallet-owned outputs referenced by the new transaction's inputs as spent
	// and creates new UTXOs for any outputs that are spendable by the wallet.
	// This keeps the transaction record and UTXO set consistent.
	//
	// CreateTx is also responsible for recording transaction metadata
	// required by higher-level wallet policy:
	//   - the received timestamp (stored in UTC),
	//   - the optional block assignment (confirmed vs unconfirmed),
	//   - the caller-selected initial transaction status.
	//
	// The create path does not infer whether an unmined transaction should
	// start in TxStatusPending or TxStatusPublished; callers must provide that
	// choice explicitly in CreateTxParams.
	CreateTx(ctx context.Context, params CreateTxParams) error

	// UpdateTx patches the mutable metadata for one existing wallet-scoped
	// transaction record.
	//
	// UpdateTx can update the user-visible label, the chain-state view
	// (block/status), or both in one atomic write. It never rewrites
	// immutable transaction facts such as the serialized transaction bytes,
	// created credits, or spent-input edges.
	//
	// UpdateTx is row-local only. It may attach, replace, or clear confirming
	// block metadata for one tx, but it must not perform branch invalidation.
	// Callers must use CreateTx, InvalidateUnminedTx, or RollbackToBlock for
	// graph-affecting lifecycle changes.
	UpdateTx(ctx context.Context, params UpdateTxParams) error

	// ApplyTxBatch atomically records a batch of transaction records and an
	// optional wallet sync-tip update.
	ApplyTxBatch(ctx context.Context, params TxBatchParams) error

	// ApplyScanBatch atomically records recovery scan writes for one wallet.
	ApplyScanBatch(ctx context.Context, params ScanBatchParams) error

	// RewindWallet atomically detaches one wallet's confirmed transactions at
	// and above the block after params.Block, and updates only that wallet's
	// synced tip to params.Block. Unlike RollbackToBlock, this method is
	// wallet-scoped and must not delete shared block rows or mutate other
	// wallets' sync states.
	RewindWallet(ctx context.Context, params RewindWalletParams) error

	// GetTx retrieves a transaction record by its hash. It takes a context
	// and GetTxQuery, returning a TxInfo struct or an error if the
	// transaction is not found.
	GetTx(ctx context.Context, query GetTxQuery) (*TxInfo, error)

	// GetTxDetail retrieves one detailed wallet-scoped transaction view by
	// hash.
	GetTxDetail(ctx context.Context, query GetTxDetailQuery) (*TxDetailInfo,
		error)

	// ListTxDetails lists detailed wallet-scoped transaction views using
	// wallet tx-reader range semantics.
	ListTxDetails(ctx context.Context,
		query ListTxDetailsQuery) ([]TxDetailInfo, error)

	// ListTxns returns a slice of transaction information based on the
	// provided query parameters. It takes a context and ListTxnsQuery,
	// returning a slice of TxInfo or an error if the retrieval fails.
	ListTxns(ctx context.Context, query ListTxnsQuery) ([]TxInfo, error)

	// DeleteTx removes an unmined pending or published transaction from the
	// store. It takes a context and DeleteTxParams, returning an error if the
	// transaction is not found or the deletion fails.
	//
	// DeleteTx is intentionally narrower than a generic
	// "delete any transaction" API. Orphaned, replaced, and failed rows remain
	// part of the wallet's historical view for audit, reorg, and replacement
	// handling and therefore must not be erased through the ordinary
	// unconfirmed-deletion path.
	DeleteTx(ctx context.Context, params DeleteTxParams) error

	// InvalidateUnminedTx invalidates one unmined transaction branch as a
	// single atomic wallet event.
	//
	// This method is intended for system-driven cleanup when a wallet-owned
	// unmined transaction is no longer valid, for example after publisher-side
	// rejection or conflict handling. Implementations must invalidate the root
	// transaction and reconcile any dependent descendant state inside one
	// database transaction.
	InvalidateUnminedTx(ctx context.Context,
		params InvalidateUnminedTxParams) error

	// RollbackToBlock removes all blocks at and after a given height,
	// moving any transactions within those blocks back to the unconfirmed
	// pool. This operation is performed as a single, atomic database
	// transaction to ensure data integrity. Breaking it into smaller,
	// separate interface methods would risk leaving the database in an
	// inconsistent state if an error occurred mid-process. The current
	// approach guarantees that the rollback is either fully completed or
	// not at all.
	//
	// NOTE: This method has no wallet ID parameter and is therefore a
	// DB-wide operation affecting all wallets that share the same `blocks`
	// table.
	//
	// TODO(yy): explore performance improvement for this method.
	RollbackToBlock(ctx context.Context, height uint32) error
}

// UTXOStore defines the database actions for managing the UTXO set.
type UTXOStore interface {
	// GetUtxo retrieves a single unspent transaction output (UTXO) by its
	// outpoint. It returns a UtxoInfo struct containing the UTXO's details
	// or an error if the UTXO is not found or has been spent.
	//
	// GetUtxo treats outputs created by unmined `pending` and `published`
	// transactions as present in the wallet's UTXO set.
	GetUtxo(ctx context.Context, query GetUtxoQuery) (*UtxoInfo, error)

	// ListUTXOs returns a slice of all unspent transaction outputs (UTXOs)
	// that match the provided query parameters. This can be used to list
	// all UTXOs or filter them by account or confirmation status.
	//
	// ListUTXOs includes outputs from unmined `pending` and `published`
	// parent transactions.
	// Spendability policy such as coinbase maturity, lease state, or whether
	// a caller wants to exclude TxStatusPending parents belongs in higher-level
	// selection logic.
	ListUTXOs(ctx context.Context, query ListUtxosQuery) ([]UtxoInfo, error)

	// LeaseOutput locks a specific UTXO for a given duration, preventing
	// it from being used in coin selection. This is useful for reserving
	// UTXOs for a specific purpose, such as a pending transaction. The
	// method returns the full lease information, including its expiration
	// time. If another active lease already exists with a different lock ID,
	// the call returns ErrOutputAlreadyLeased.
	LeaseOutput(ctx context.Context, params LeaseOutputParams) (
		*LeasedOutput, error)

	// ReleaseOutput unlocks a previously leased UTXO, making it available
	// for coin selection again. Unlocking an already-unlocked or expired lease
	// is a no-op. If another active lease still exists for the output, the lock
	// ID must match the one that holds it or the call returns
	// ErrOutputUnlockNotAllowed.
	ReleaseOutput(ctx context.Context, params ReleaseOutputParams) error

	// ListLeasedOutputs returns a slice of all currently leased UTXOs whose
	// parent transaction is still `pending` or `published`.
	// This can be used to inspect which still-unspent outputs are currently
	// locked and when their leases expire.
	ListLeasedOutputs(ctx context.Context, walletID uint32) (
		[]LeasedOutput, error)

	// DeleteExpiredLeases removes expired UTXO lease records for the wallet.
	DeleteExpiredLeases(ctx context.Context, walletID uint32) error

	// ListOutputsToWatch returns UTXOs that recovery scans should watch.
	ListOutputsToWatch(ctx context.Context, walletID uint32) ([]UtxoInfo,
		error)

	// Balance returns a wallet-scoped balance view for the current unspent UTXO
	// set after applying any optional caller-supplied filters.
	//
	// The zero-value BalanceParams request the wallet's current factual
	// balance.
	// Callers may narrow that view by account, confirmation range, lease
	// or coinbase maturity when they need a workflow-specific balance policy
	// from the public store interface. The returned BalanceResult always uses
	// the same filtered base set for both Total and Locked so callers can
	// reason about lease state without issuing a second balance query.
	Balance(ctx context.Context, params BalanceParams) (
		BalanceResult, error)
}
