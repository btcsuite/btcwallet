package wallet

import (
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// Interface defines the public API for a wallet.
//
// This interface is intended to be the primary way that other packages and
// applications interact with a wallet. It defines a stable, high-level
// contract that abstracts away the underlying implementation details, making
// it easier to build applications on top of the wallet and to create mock
// implementations for testing.
//
//nolint:interfacebloat
type Interface interface {
	// Start starts the goroutines necessary to manage a wallet.
	Start()

	// Stop signals all wallet goroutines to shutdown.
	Stop()

	// WaitForShutdown blocks until all wallet goroutines have finished.
	WaitForShutdown()

	// SynchronizeRPC associates the wallet with the consensus RPC client.
	SynchronizeRPC(chainClient chain.Interface)

	// Locked returns whether the wallet is locked. When locked, any
	// operations that require private key access, such as spending funds,
	// will fail.
	Locked() bool

	// Unlock unlocks the wallet with a passphrase. The wallet will
	// automatically re-lock after the timeout has expired. If the timeout
	// channel is nil, the wallet remains unlocked indefinitely.
	Unlock(passphrase []byte, lock <-chan time.Time) error

	// Lock locks the wallet. Any operations that require private keys will
	// fail until the wallet is unlocked again.
	Lock()

	// ChainSynced returns whether the wallet is synchronized with the
	// blockchain. Certain operations may fail if the wallet is not synced.
	ChainSynced() bool

	// SyncedTo returns details about the block height and hash that the
	// address manager is synced through at the very least. The intention
	// is that callers can use this information for intelligently
	// initiating rescans to sync back to the best chain from the last
	// known good block.
	SyncedTo() waddrmgr.BlockStamp

	// BirthdayBlock returns the wallet's birthday block.
	BirthdayBlock() (*waddrmgr.BlockStamp, error)

	// Database returns the underlying walletdb database. This method is
	// provided in order to allow applications wrapping btcwallet to store
	// app-specific data with the wallet's database.
	Database() walletdb.DB

	// ChainParams returns the chain parameters for the wallet.
	ChainParams() *chaincfg.Params

	// NotificationServer returns the internal NotificationServer.
	NotificationServer() *NotificationServer

	// AddrManager returns the internal address manager.
	AddrManager() *waddrmgr.Manager

	// Accounts returns all accounts for a particular scope.
	Accounts(scope waddrmgr.KeyScope) (*AccountsResult, error)

	// AccountProperties returns the properties for a specific account,
	// such as its name, key counts, and public key information.
	AccountProperties(scope waddrmgr.KeyScope, account uint32) (
		*waddrmgr.AccountProperties, error,
	)

	// AccountPropertiesByName returns the properties of an account by its
	// name.
	AccountPropertiesByName(scope waddrmgr.KeyScope,
		name string) (*waddrmgr.AccountProperties, error)

	// AccountNumber returns the account number for a given account name
	// and key scope.
	AccountNumber(scope waddrmgr.KeyScope, accountName string) (
		uint32, error)

	// AccountName returns the name for a given account number and key
	// scope.
	AccountName(scope waddrmgr.KeyScope, accountNumber uint32) (
		string, error)

	// AccountManagedAddresses returns the managed addresses for every
	// created address for an account.
	AccountManagedAddresses(scope waddrmgr.KeyScope,
		accountNum uint32) ([]waddrmgr.ManagedAddress, error)

	// RenameAccountDeprecated renames an existing account. It is an error
	// to rename a reserved account or to choose a name that is already in
	// use.
	//
	// Deprecated: Use AccountManager.RenameAccount instead.
	RenameAccountDeprecated(scope waddrmgr.KeyScope, account uint32,
		newName string) error

	// ImportAccountDeprecated imports an account backed by an extended
	// public key.
	//
	// This creates a watch-only account.
	//
	// Deprecated: Use AccountManager.ImportAccount instead.
	ImportAccountDeprecated(name string,
		accountPubKey *hdkeychain.ExtendedKey,
		masterKeyFingerprint uint32, addrType *waddrmgr.AddressType,
	) (*waddrmgr.AccountProperties, error)

	// ImportAccountDryRun imports an account backed by an extended public
	// key, but does not save it to the database. This is useful for
	// validating an account before importing it.
	ImportAccountDryRun(name string, accountPubKey *hdkeychain.ExtendedKey,
		masterKeyFingerprint uint32, addrType *waddrmgr.AddressType,
		numAddrs uint32) (*waddrmgr.AccountProperties,
		[]waddrmgr.ManagedAddress, []waddrmgr.ManagedAddress, error)

	// InitAccounts initializes the accounts for all the key families.
	InitAccounts(scope *waddrmgr.ScopedKeyManager, convertToWatchOnly bool,
		account uint32) error

	// AddScopeManager adds a new scope manager to the wallet.
	AddScopeManager(scope waddrmgr.KeyScope,
		addrSchema waddrmgr.ScopeAddrSchema) (
		*waddrmgr.ScopedKeyManager, error)

	// CurrentAddress returns the current, most recently generated address
	// for a given account and scope. If the current address has been used,
	// a new one is derived and returned.
	CurrentAddress(account uint32, scope waddrmgr.KeyScope) (
		btcutil.Address, error)

	// NewAddress returns a new address for a given account and scope.
	NewAddress(account uint32, scope waddrmgr.KeyScope) (
		btcutil.Address, error)

	// NewChangeAddress returns a new change address for a given account
	// and scope.
	NewChangeAddress(account uint32, scope waddrmgr.KeyScope) (
		btcutil.Address, error)

	// AddressInfo returns detailed information about a managed address,
	// including its derivation path and whether it's compressed.
	AddressInfo(a btcutil.Address) (waddrmgr.ManagedAddress, error)

	// HaveAddress returns whether the wallet is the owner of the address.
	HaveAddress(a btcutil.Address) (bool, error)

	// ImportPublicKey imports a public key as a watch-only address.
	ImportPublicKey(pubKey *btcec.PublicKey,
		addrType waddrmgr.AddressType) error

	// ImportTaprootScript imports a taproot script into the wallet.
	ImportTaprootScript(scope waddrmgr.KeyScope,
		tapscript *waddrmgr.Tapscript, bs *waddrmgr.BlockStamp,
		witnessVersion byte, isSecretScript bool) (
		waddrmgr.ManagedAddress, error)

	// FetchDerivationInfo returns the derivation information for a given
	// set of addresses.
	FetchDerivationInfo(pkScript []byte) (*psbt.Bip32Derivation, error)

	// CalculateBalance returns the wallet's total balance for a given
	// number of required confirmations.
	CalculateBalance(requiredConfirmations int32) (btcutil.Amount, error)

	// CalculateAccountBalances returns the balances for a specific account.
	CalculateAccountBalances(account uint32, requiredConfirmations int32) (
		Balances, error)

	// ListUnspent returns all unspent transaction outputs for a given
	// account and confirmation requirement.
	ListUnspent(minconf, maxconf int32, accountName string) (
		[]*btcjson.ListUnspentResult, error)

	// FetchOutpointInfo returns the output information for a given
	// outpoint.
	FetchOutpointInfo(prevOut *wire.OutPoint) (
		*wire.MsgTx, *wire.TxOut, int64, error)

	// LockOutpoint locks a specific UTXO, preventing it from being used in
	// coin selection. The lock is identified by a unique ID and has an
	// expiration time.
	LockOutpoint(op wire.OutPoint)

	// UnlockOutpoint unlocks a previously locked UTXO, making it available
	// for coin selection again.
	UnlockOutpoint(op wire.OutPoint)

	// LockedOutpoint returns whether an outpoint has been marked as locked
	// and should not be used as an input for created transactions.
	LockedOutpoint(op wire.OutPoint) bool

	// LeaseOutput locks an output to the given ID, preventing it from
	// being available for coin selection. The absolute time of the lock's
	// expiration is returned. The expiration of the lock can be extended by
	// successive invocations of this call.
	//
	// Outputs can be unlocked before their expiration through
	// `UnlockOutput`. Otherwise, they are unlocked lazily through calls
	// which iterate through all known outputs, e.g., `CalculateBalance`,
	// `ListUnspent`.
	//
	// If the output is not known, ErrUnknownOutput is returned. If the
	// output has already been locked to a different ID, then
	// ErrOutputAlreadyLocked is returned.
	//
	// NOTE: This differs from LockOutpoint in that outputs are locked for
	// a limited amount of time and their locks are persisted to disk.
	LeaseOutput(id wtxmgr.LockID, op wire.OutPoint,
		duration time.Duration) (time.Time, error)

	// ReleaseOutput unlocks an output, allowing it to be available for
	// coin selection if it remains unspent. The ID should match the one
	// used to originally lock the output.
	ReleaseOutput(id wtxmgr.LockID, op wire.OutPoint) error

	// ListLeasedOutputs returns a list of all currently leased outputs.
	ListLeasedOutputs() ([]*ListLeasedOutputResult, error)

	// CreateSimpleTx creates a new transaction to the specified outputs,
	// automatically performing coin selection and creating a change output
	// if necessary.
	CreateSimpleTx(coinSelectKeyScope *waddrmgr.KeyScope, account uint32,
		outputs []*wire.TxOut, minconf int32, satPerKb btcutil.Amount,
		strategy CoinSelectionStrategy, dryRun bool,
		optFuncs ...TxCreateOption) (*txauthor.AuthoredTx, error)

	// SendOutputs funds, signs, and broadcasts a Bitcoin transaction
	// paying out to the specified outputs.
	SendOutputs(outputs []*wire.TxOut,
		coinSelectKeyScope *waddrmgr.KeyScope, account uint32,
		minconf int32, satPerKb btcutil.Amount,
		strategy CoinSelectionStrategy, label string) (*wire.MsgTx, error)

	// SendOutputsWithInput is a variant of SendOutputs that allows
	// specifying a particular input to use for the transaction.
	SendOutputsWithInput(outputs []*wire.TxOut,
		coinSelectKeyScope *waddrmgr.KeyScope, account uint32,
		minconf int32, satPerKb btcutil.Amount,
		strategy CoinSelectionStrategy, label string,
		inputs []wire.OutPoint) (*wire.MsgTx, error)

	// PublishTransaction broadcasts a transaction to the network.
	PublishTransaction(tx *wire.MsgTx, label string) error

	// FundPsbt creates a PSBT with enough inputs to fund the specified
	// outputs, adding a change output if necessary.
	FundPsbt(packet *psbt.Packet, keyScope *waddrmgr.KeyScope,
		minConfs int32, account uint32, feeSatPerKB btcutil.Amount,
		strategy CoinSelectionStrategy,
		optFuncs ...TxCreateOption) (int32, error)

	// FinalizePsbt signs and finalizes a PSBT, making it ready for
	// broadcast. The wallet must be the last signer.
	FinalizePsbt(keyScope *waddrmgr.KeyScope, account uint32,
		packet *psbt.Packet) error

	// DecorateInputs decorates the inputs of a PSBT with the necessary
	// information to sign it.
	DecorateInputs(packet *psbt.Packet, failOnUnknown bool) error

	// GetTransaction returns the details for a transaction given its hash.
	GetTransaction(txHash chainhash.Hash) (*GetTransactionResult, error)

	// GetTransactions returns a slice of transaction details for
	// transactions which fall in the given range of blocks.
	GetTransactions(start *BlockIdentifier, end *BlockIdentifier,
		accountFilter string, txFilter <-chan struct{}) (
		*GetTransactionsResult, error)

	// LabelTransaction adds or overwrites a label for a given transaction.
	LabelTransaction(hash chainhash.Hash, label string,
		overwrite bool) error

	// RemoveDescendants removes all transactions from the wallet that
	// spend outputs from the passed transaction.
	RemoveDescendants(tx *wire.MsgTx) error

	// PrivKeyForAddress returns the private key for a given address.
	PrivKeyForAddress(a btcutil.Address) (*btcec.PrivateKey, error)

	// DeriveFromKeyPath derives a key from the wallet's root key.
	DeriveFromKeyPath(scope waddrmgr.KeyScope,
		path waddrmgr.DerivationPath) (*btcec.PrivateKey, error)

	// DeriveFromKeyPathAddAccount derives a key from the wallet's root
	// key, also creating a new account if it doesn't exist.
	DeriveFromKeyPathAddAccount(scope waddrmgr.KeyScope,
		path waddrmgr.DerivationPath) (*btcec.PrivateKey, error)

	// ComputeInputScript generates a complete InputScript for the passed
	// transaction with the signature as defined within the passed
	// SignDescriptor.
	ComputeInputScript(tx *wire.MsgTx, output *wire.TxOut,
		inputIndex int, sigHashes *txscript.TxSigHashes,
		hashType txscript.SigHashType,
		tweaker PrivKeyTweaker) (wire.TxWitness, []byte, error)

	// ScriptForOutput returns the address, witness program and redeem
	// script for a given UTXO.
	ScriptForOutput(output *wire.TxOut) (waddrmgr.ManagedPubKeyAddress,
		[]byte, []byte, error)
}

// A compile time check to ensure that Wallet implements the interface.
var _ Interface = (*Wallet)(nil)
