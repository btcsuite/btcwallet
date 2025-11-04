package db

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
)

// WalletStore defines the methods for wallet-level operations.
type WalletStore interface {
	// CreateWallet creates a new wallet in the database with the provided
	// parameters. It returns the ID of the newly created wallet or an error
	// if the creation fails.
	CreateWallet(ctx context.Context, params CreateWalletParams) (
		*WalletInfo, error)

	// GetWallet retrieves information about a wallet given its name. It
	// returns a WalletInfo struct containing the wallet's properties or an
	// error if the wallet is not found.
	GetWallet(ctx context.Context, name string) (*WalletInfo, error)

	// ListWallets returns a slice of WalletInfo for all wallets stored in
	// the database. It returns an empty slice if no wallets are found, or
	// an error if the retrieval fails.
	ListWallets(ctx context.Context) ([]WalletInfo, error)

	// UpdateWallet updates various properties of a wallet, such as its
	// birthday, birthday block, or sync state. The specific fields to
	// update are provided in the UpdateWalletParams struct. It returns an
	// error if the update fails.
	UpdateWallet(ctx context.Context, params UpdateWalletParams) error

	// GetEncryptedHDSeed retrieves the encrypted Hierarchical
	// Deterministic (HD) seed of the wallet. This seed is sensitive
	// information and is returned in its encrypted form. It returns the
	// encrypted seed as a byte slice or an error if the retrieval fails.
	GetEncryptedHDSeed(ctx context.Context, walletID uint32) ([]byte, error)

	// ChangePassphrase changes the passphrase for the wallet. It takes the
	// old and new passphrases as byte slices, and a boolean indicating
	// whether to change the private passphrase (true) or the public
	// passphrase (false). It returns an error if the passphrase change
	// fails (e.g., incorrect old passphrase).
	ChangePassphrase(ctx context.Context,
		params ChangePassphraseParams) error
}

// AccountStore defines the database actions for managing accounts.
type AccountStore interface {
	// CreateAccount creates a new account with the given name and scope. It
	// returns the properties of the newly created account or an error if
	// the
	// creation fails.
	CreateAccount(ctx context.Context, params CreateAccountParams) (
		*AccountInfo, error)

	// ImportAccount imports an account from an extended key. This method
	// supports normal imports, imports with a specific scope, and dry-run
	// imports. The behavior is controlled by the fields in the
	// ImportAccountParams struct. It returns the properties of the imported
	// account and derived addresses (for dry runs) or an error if the
	// import fails. The returned addresses are of type AddressInfo.
	ImportAccount(ctx context.Context, params ImportAccountParams) (
		*ImportAccountResult, error)

	// GetAccount retrieves information about a specific account,
	// identified by its name or account number within a given key scope.
	// It returns an AccountInfo struct containing the account's properties
	// or an error if the account is not found.
	GetAccount(ctx context.Context, query GetAccountQuery) (
		*AccountInfo, error)

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

// AddressStore defines the database actions for managing addresses.
type AddressStore interface {
	// NewAddress creates a new address for a given account and key scope.
	// It returns the newly created address or an error if the creation
	// fails.
	NewAddress(ctx context.Context, params NewAddressParams) (
		btcutil.Address, error)

	// ImportAddress imports a new address, script, or private key. If a
	// private key is provided in the parameters, the address will be
	// spendable. Otherwise, it will be imported as watch-only. It returns
	// information about the imported address or an error if the import
	// fails.
	ImportAddress(ctx context.Context, params ImportAddressParams) (
		*AddressInfo, error)

	// GetAddress retrieves information about a specific address. It
	// returns an AddressInfo struct containing the address's properties or
	// an error if the address is not found.
	GetAddress(ctx context.Context, query GetAddressQuery) (
		*AddressInfo, error)

	// ListAddresses returns a slice of AddressInfo for all addresses in a
	// given account. It returns an empty slice if no addresses are found.
	ListAddresses(ctx context.Context, query ListAddressesQuery) (
		[]AddressInfo, error)

	// MarkAddressAsUsed marks a given address as used. This is used to
	// ensure that the address is not reused.
	MarkAddressAsUsed(ctx context.Context,
		params MarkAddressAsUsedParams) error

	// GetPrivateKey retrieves the private key for a given address. This
	// method is ONLY valid for addresses that were imported with a private
	// key. It will return an error for derived HD addresses and watch-only
	// imports.
	GetPrivateKey(ctx context.Context, params GetPrivateKeyParams) (
		*btcec.PrivateKey, error)
}

// TxStore defines the database actions for managing transaction records.
type TxStore interface {
	// CreateTx atomically records a transaction and its associated credits
	// in the database. This is a single atomic operation that also handles
	// the corresponding UTXO state changes: it will delete any UTXOs spent
	// by the new transaction's inputs and create new UTXOs for any of its
	// outputs that are spendable by the wallet. This ensures that the
	// transaction record and the UTXO set are always consistent.
	CreateTx(ctx context.Context, params CreateTxParams) error

	// UpdateTx updates an existing transaction record in the database. It
	// takes a context and UpdateTxParams, returning an error if the
	// transaction cannot be found or updated.
	UpdateTx(ctx context.Context, params UpdateTxParams) error

	// GetTx retrieves a transaction record by its hash. It takes a context
	// and GetTxQuery, returning a TxInfo struct or an error if the
	// transaction is not found. Note that the `Credits` and `Debits` fields
	// of the returned `TxInfo` are not stored directly in the transaction
	// record; they are derived by querying the UTXO store and represent
	// wallet-specific information about the transaction's impact on the
	// UTXO set.
	GetTx(ctx context.Context, query GetTxQuery) (*TxInfo, error)

	// ListTxns returns a slice of transaction information based on the
	// provided query parameters. It takes a context and ListTxnsQuery,
	// returning a slice of TxInfo or an error if the retrieval fails.
	ListTxns(ctx context.Context, query ListTxnsQuery) ([]TxInfo, error)

	// DeleteTx removes an unmined transaction from the store. It takes a
	// context and DeleteTxParams, returning an error if the transaction is
	// not found or the deletion fails.
	DeleteTx(ctx context.Context, params DeleteTxParams) error

	// RollbackToBlock removes all blocks at and after a given height,
	// moving any transactions within those blocks back to the unconfirmed
	// pool. This operation is performed as a single, atomic database
	// transaction to ensure data integrity. Breaking it into smaller,
	// separate interface methods would risk leaving the database in an
	// inconsistent state if an error occurred mid-process. The current
	// approach guarantees that the rollback is either fully completed or
	// not at all.
	//
	// TODO(yy): explore performance improvement for this method.
	RollbackToBlock(ctx context.Context, height uint32) error
}

// UTXOStore defines the database actions for managing the UTXO set.
type UTXOStore interface {
	// GetUtxo retrieves a single unspent transaction output (UTXO) by its
	// outpoint. It returns a UtxoInfo struct containing the UTXO's details
	// or an error if the UTXO is not found or has been spent.
	GetUtxo(ctx context.Context, query GetUtxoQuery) (*UtxoInfo, error)

	// ListUTXOs returns a slice of all unspent transaction outputs (UTXOs)
	// that match the provided query parameters. This can be used to list
	// all UTXOs or filter them by account or confirmation status.
	ListUTXOs(ctx context.Context, query ListUtxosQuery) ([]UtxoInfo, error)

	// LeaseOutput locks a specific UTXO for a given duration, preventing
	// it from being used in coin selection. This is useful for reserving
	// UTXOs for a specific purpose, such as a pending transaction. The
	// method returns the full lease information, including its expiration
	// time.
	LeaseOutput(ctx context.Context, params LeaseOutputParams) (
		*LeasedOutput, error)

	// ReleaseOutput unlocks a previously leased UTXO, making it available
	// for coin selection again. The lock ID must match the one used to
	// lease the output.
	ReleaseOutput(ctx context.Context, params ReleaseOutputParams) error

	// ListLeasedOutputs returns a slice of all currently leased UTXOs.
	// This can be used to inspect which outputs are currently locked and
	// when their leases expire.
	ListLeasedOutputs(ctx context.Context, walletID uint32) (
		[]LeasedOutput, error)

	// Balance returns the total spendable balance of the wallet,
	// calculated from the UTXO set. The minConfirms parameter specifies
	// the minimum number of confirmations a UTXO must have to be included
	// in the balance calculation.
	Balance(ctx context.Context, params BalanceParams) (
		btcutil.Amount, error)
}
