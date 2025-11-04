// Package db provides a database-agnostic interface for wallet data storage,
// defining the core data types and store interfaces for wallets, accounts,
// addresses, transactions, and UTXOs.
package db

import (
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// ============================================================================
// Data Types & Method Parameters
// ============================================================================

// KeyScope represents the BIP-44 key scope as defined in BIP-43. It is used
// to organize keys based on their purpose and coin type, providing a
// hierarchical structure for key derivation.
type KeyScope struct {
	// Purpose is the purpose number for the scope, as defined in BIP-43.
	Purpose uint32

	// Coin is the coin type number for the scope, as defined in BIP-44.
	Coin uint32
}

// AddressType specifies the type of a managed address. This is used to
// identify the script type of an address, such as P2PKH, P2SH, P2WKH, etc.
type AddressType uint8

const (
	// PubKeyHash represents a pay-to-pubkey-hash (P2PKH) address.
	PubKeyHash AddressType = iota

	// ScriptHash represents a pay-to-script-hash (P2SH) address.
	ScriptHash

	// WitnessPubKey represents a pay-to-witness-pubkey-hash (P2WKH)
	// address.
	WitnessPubKey

	// NestedWitnessPubKey represents a P2WKH output nested within a P2SH
	// address.
	NestedWitnessPubKey

	// TaprootPubKey represents a pay-to-taproot (P2TR) address.
	TaprootPubKey
)

const (
	// BIP0044Purpose is the purpose field for BIP0044 derivation.
	BIP0044Purpose = 44

	// BIP0049Purpose is the purpose field for BIP0049 derivation.
	BIP0049Purpose = 49

	// BIP0084Purpose is the purpose field for BIP0084 derivation.
	BIP0084Purpose = 84

	// BIP0086Purpose is the purpose field for BIP0086 derivation.
	BIP0086Purpose = 86
)

var (
	// KeyScopeBIP0049Plus is the key scope of our modified BIP0049
	// derivation. We say this is BIP0049 "plus", as it acts as an
	// optimization for fee savings. Standard BIP0049 uses P2SH-wrapped
	// SegWit for both external (receive) and internal (change) addresses.
	// This scheme uses P2SH-wrapped SegWit for external addresses (to
	// ensure backward compatibility with senders using legacy wallets) but
	// uses Native SegWit (P2WKH) for internal change addresses. Since the
	// wallet controls its own change, it can use the more efficient Native
	// SegWit format to reduce transaction weight and save on fees when
	// spending that change later.
	KeyScopeBIP0049Plus = KeyScope{
		Purpose: BIP0049Purpose,
		Coin:    0,
	}

	// KeyScopeBIP0084 is the key scope for BIP0084 derivation. BIP0084
	// will be used to derive all p2wkh addresses.
	KeyScopeBIP0084 = KeyScope{
		Purpose: BIP0084Purpose,
		Coin:    0,
	}

	// KeyScopeBIP0086 is the key scope for BIP0086 derivation. BIP0086
	// will be used to derive all p2tr addresses.
	KeyScopeBIP0086 = KeyScope{
		Purpose: BIP0086Purpose,
		Coin:    0,
	}

	// KeyScopeBIP0044 is the key scope for BIP0044 derivation. Legacy
	// wallets will only be able to use this key scope, and no keys beyond
	// it.
	KeyScopeBIP0044 = KeyScope{
		Purpose: BIP0044Purpose,
		Coin:    0,
	}

	// ScopeAddrMap is a map from the default key scopes to the scope
	// address schema for each scope type.
	ScopeAddrMap = map[KeyScope]ScopeAddrSchema{
		KeyScopeBIP0049Plus: {
			ExternalAddrType: NestedWitnessPubKey,
			InternalAddrType: WitnessPubKey,
		},
		KeyScopeBIP0084: {
			ExternalAddrType: WitnessPubKey,
			InternalAddrType: WitnessPubKey,
		},
		KeyScopeBIP0086: {
			ExternalAddrType: TaprootPubKey,
			InternalAddrType: TaprootPubKey,
		},
		KeyScopeBIP0044: {
			InternalAddrType: PubKeyHash,
			ExternalAddrType: PubKeyHash,
		},
	}
)

// Tapscript represents a Taproot script leaf, which includes the script itself
// and its corresponding control block. This is used for spending Taproot
// outputs.
type Tapscript struct {
	// ControlBlock is the control block for the Taproot script, which is
	// required to reveal the script path during spending.
	ControlBlock []byte

	// Script is the actual script code of the Taproot leaf.
	Script []byte
}

// --------------------
// WalletStore Types
// --------------------

// WalletInfo contains the static properties of a wallet. This struct provides a
// summary of the wallet's configuration and state.
type WalletInfo struct {
	// ID is the unique identifier for the wallet.
	//
	// NOTE: This is a uint32 rather than a uint64 to ensure compatibility
	// with standard SQL databases (PostgreSQL, SQLite) which typically use
	// signed 64-bit integers for their BIGINT/INTEGER types. A uint64 can
	// overflow a signed 64-bit integer, whereas a uint32 fits comfortably.
	ID uint32

	// Name is the human-readable name of the wallet.
	Name string

	// IsImported indicates whether the wallet was created from an existing
	// seed or was created as a new wallet.
	IsImported bool

	// IsWatchOnly indicates whether the wallet is in watch-only mode,
	// meaning it does not have private keys and cannot sign transactions.
	IsWatchOnly bool

	// Birthday is the timestamp of the wallet's creation, used as a
	// starting point for rescans.
	Birthday time.Time

	// BirthdayBlock is the block hash and height from which to start a
	// rescan.
	BirthdayBlock Block

	// SyncedTo represents the wallet's current synchronization state with
	// the blockchain.
	SyncedTo *Block
}

// Block defines a block's hash, height, and timestamp. This is used to
// represent a block's identity and position in the blockchain.
type Block struct {
	// Hash is the 32-byte hash of the block.
	Hash chainhash.Hash

	// Height is the height of the block in the blockchain.
	Height uint32

	// Timestamp is the timestamp of the block, which is used for wallet
	// synchronization and rescan operations.
	Timestamp time.Time
}

// CreateWalletParams contains the parameters required to create a new wallet.
type CreateWalletParams struct {
	// Name is the name of the new wallet.
	Name string

	// IsImported should be set to true if the wallet is being created from
	// an existing seed.
	IsImported bool

	// IsWatchOnly indicates whether the wallet is being created in
	// watch-only mode.
	IsWatchOnly bool

	// EncryptedMasterPrivKey is the encrypted master HD private key.
	EncryptedMasterPrivKey []byte

	// EncryptedMasterPubKey is the encrypted master HD public key.
	EncryptedMasterPubKey []byte

	// MasterKeyPubParams are the parameters (e.g. salt, scrypt N/R/P) used
	// to derive the master public key.
	MasterKeyPubParams []byte

	// MasterKeyPrivParams are the parameters (e.g. salt, scrypt N/R/P) used
	// to derive the master private key.
	MasterKeyPrivParams []byte

	// EncryptedCryptoPrivKey is the encrypted private crypto key, used to
	// protect private keys in the database.
	EncryptedCryptoPrivKey []byte

	// EncryptedCryptoPubKey is the encrypted public crypto key, used to
	// protect public keys in the database.
	EncryptedCryptoPubKey []byte

	// EncryptedCryptoScriptKey is the encrypted script crypto key, used to
	// protect scripts in the database.
	EncryptedCryptoScriptKey []byte
}

// UpdateWalletParams contains the parameters for updating a wallet's
// properties. Fields are pointers to allow for partial updates.
type UpdateWalletParams struct {
	// WalletID is the ID of the wallet to update.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// Birthday is the new birthday for the wallet.
	Birthday *time.Time

	// BirthdayBlock is the new birthday block for the wallet.
	BirthdayBlock *Block

	// SyncedTo is the new synchronization state for the wallet.
	SyncedTo *Block
}

// ChangePassphraseParams contains the parameters for changing a wallet's
// passphrase.
type ChangePassphraseParams struct {
	// WalletID is the ID of the wallet to update.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// OldPassphrase is the current passphrase.
	OldPassphrase []byte

	// NewPassphrase is the new passphrase to set.
	NewPassphrase []byte

	// IsPrivate specifies whether to change the private (true) or public
	// (false) passphrase.
	IsPrivate bool
}

// --------------------
// AccountStore Types
// --------------------

// AccountInfo contains all information about a single account, including its
// properties and balances.
type AccountInfo struct {
	// AccountNumber is the unique identifier for the account.
	AccountNumber uint32

	// AccountName is the human-readable name of the account.
	AccountName string

	// ExternalKeyCount is the number of external keys that have been
	// derived.
	ExternalKeyCount uint32

	// InternalKeyCount is the number of internal (change) keys that have
	// been derived.
	InternalKeyCount uint32

	// ImportedKeyCount is the number of imported keys in the account.
	ImportedKeyCount uint32

	// ConfirmedBalance is the total balance of the account from confirmed
	// transactions.
	ConfirmedBalance btcutil.Amount

	// UnconfirmedBalance is the total balance of the account from
	// unconfirmed transactions.
	UnconfirmedBalance btcutil.Amount

	// IsWatchOnly indicates whether the account is in watch-only mode.
	IsWatchOnly bool

	// KeyScope is the key scope the account belongs to. This determines the
	// derivation path and the default address schema.
	KeyScope KeyScope
}

// ScopeAddrSchema is the address schema of a particular KeyScope. This will be
// persisted within the database, and will be consulted when deriving any keys
// for a particular scope to know how to encode the public keys as addresses.
type ScopeAddrSchema struct {
	// ExternalAddrType is the address type for all keys within branch 0.
	ExternalAddrType AddressType

	// InternalAddrType is the address type for all keys within branch 1
	// (change addresses).
	InternalAddrType AddressType
}

// CreateAccountParams contains the parameters for creating a new account.
type CreateAccountParams struct {
	// WalletID is the ID of the wallet to create the account in.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// Scope is the key scope for the new account.
	Scope KeyScope

	// Name is the name of the new account.
	Name string
}

// ImportAccountParams contains the data required to import an account from an
// extended key.
type ImportAccountParams struct {
	// WalletID is the ID of the wallet to import the account into.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// Name is the name of the account to import.
	Name string

	// AccountKey is the extended key for the account.
	AccountKey *hdkeychain.ExtendedKey

	// MasterKeyFingerprint is the fingerprint of the master key.
	MasterKeyFingerprint uint32

	// Scope is the key scope for the account. The address schema for the
	// account will be determined by the default mapping for this scope.
	Scope KeyScope
}

// ImportAccountResult holds the results of an account import operation.
type ImportAccountResult struct {
	// AccountProperties contains the properties of the imported account.
	AccountProperties *AccountProperties

	// ExternalAddrs contains the derived external addresses if the import
	// was a dry run.
	ExternalAddrs []AddressInfo

	// InternalAddrs contains the derived internal addresses if the import
	// was a dry run.
	InternalAddrs []AddressInfo
}

// AccountProperties contains properties associated with each account, such as
// the account name, number, and the nubmer of derived and imported keys.
type AccountProperties struct {
	// AccountNumber is the internal number used to reference the account.
	AccountNumber uint32

	// AccountName is the user-identifying name of the account.
	AccountName string

	// ExternalKeyCount is the number of internal keys that have been
	// derived for the account.
	ExternalKeyCount uint32

	// InternalKeyCount is the number of internal keys that have been
	// derived for the account.
	InternalKeyCount uint32

	// ImportedKeyCount is the number of imported keys found within the
	// account.
	ImportedKeyCount uint32

	// AccountPubKey is the account's public key that can be used to
	// derive any address relevant to said account.
	//
	// NOTE: This may be nil for imported accounts.
	AccountPubKey *hdkeychain.ExtendedKey

	// MasterKeyFingerprint represents the fingerprint of the root key
	// corresponding to the master public key (also known as the key with
	// derivation path m/). This may be required by some hardware wallets
	// for proper identification and signing.
	MasterKeyFingerprint uint32

	// KeyScope is the key scope the account belongs to.
	KeyScope KeyScope

	// IsWatchOnly indicates whether the is set up as watch-only, i.e., it
	// doesn't contain any private key information.
	IsWatchOnly bool

	// AddrSchema, if non-nil, specifies an address schema override for
	// address generation only applicable to the account.
	AddrSchema *ScopeAddrSchema
}

// GetAccountQuery contains the parameters for querying a single account. The
// query must specify either the account name or the account number. Using
// pointers for these fields allows the query to be unambiguous, as a nil value
// indicates that the field should not be used for filtering. This avoids the
// "zero value" problem, where 0 or an empty string could be valid query
// targets.
type GetAccountQuery struct {
	// WalletID is the ID of the wallet to query.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// Scope is the key scope of the account.
	Scope KeyScope

	// Name is the name of the account to query. If nil, the query will be
	// performed using the AccountNumber.
	Name *string

	// AccountNumber is the number of the account to query. If nil, the
	// query will be performed using the Name.
	AccountNumber *uint32
}

// ListAccountsQuery holds the set of options for a ListAccounts query.
type ListAccountsQuery struct {
	// WalletID is the ID of the wallet to query.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// Scope is an optional filter to list accounts only for a specific key
	// scope.
	Scope *KeyScope

	// Name is an optional filter to list accounts only with a specific
	// name.
	Name *string
}

// RenameAccountParams contains the parameters for renaming an account. The
// account can be identified by either its old name or its account number.
type RenameAccountParams struct {
	// WalletID is the ID of the wallet containing the account.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// Scope is the key scope of the account.
	Scope KeyScope

	// OldName is the current name of the account. This is used to identify
	// the account if AccountNumber is not provided.
	OldName string

	// AccountNumber is the number of the account to rename. This is used
	// to identify the account if OldName is not provided.
	AccountNumber *uint32

	// NewName is the new name for the account.
	NewName string
}

// --------------------
// AddressStore Types
// --------------------

// AddressInfo represents a wallet-managed address, including its properties and
// derivation information.
type AddressInfo struct {
	// Address is the human-readable address string.
	Address btcutil.Address

	// Internal indicates whether the address is for internal (change) use.
	Internal bool

	// Compressed indicates whether the address is compressed.
	Compressed bool

	// Used indicates whether the address has been used in a transaction.
	Used bool

	// IsWatchOnly indicates whether the wallet has the private key for
	// this address.
	IsWatchOnly bool

	// AddrType is the type of the address (P2PKH, P2SH, etc.).
	AddrType AddressType

	// DerivationInfo contains the BIP-32 derivation path information for
	// the address. This will be nil for imported addresses that are not
	// part of an HD account.
	DerivationInfo *DerivationInfo

	// Script is the script associated with the address, if any.
	Script []byte
}

// NewAddressParams contains the parameters for creating a new address.
type NewAddressParams struct {
	// WalletID is the ID of the wallet to create the address in.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// AccountName is the name of the account to create the address for.
	AccountName string

	// Scope is the key scope for the new address.
	Scope KeyScope

	// Change indicates whether to create a change address (true) or an
	// external address (false).
	Change bool
}

// ImportAddressParams encapsulates all the data needed to store a new, imported
// address, script, or private key. All imported addresses are automatically
// assigned to the wallet's logical "imported" account. The presence of a
// private key determines whether the address will be spendable or watch-only.
type ImportAddressParams struct {
	// WalletID is the ID of the wallet to import the address into.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// PrivateKey is the private key to import, in WIF format. If this is
	// provided, the address will be spendable. If nil, the import will be
	// watch-only.
	PrivateKey *btcutil.WIF

	// PubKey is the public key to import for a watch-only address. This
	// field is only used if PrivateKey is nil.
	PubKey *btcec.PublicKey

	// Tapscript is the Taproot script to import for a watch-only address.
	// This field is only used if PrivateKey is nil.
	Tapscript *Tapscript

	// Script is the generic script to import for a watch-only address.
	// This field is only used if PrivateKey is nil.
	Script []byte
}

// GetPrivateKeyParams contains the parameters for retrieving a private key.
type GetPrivateKeyParams struct {
	// WalletID is the ID of the wallet to query.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// Address is the address for which to retrieve the private key.
	Address btcutil.Address
}

// GetAddressQuery contains the parameters for querying an address.
type GetAddressQuery struct {
	// WalletID is the ID of the wallet to query.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// Address is the address to query.
	Address btcutil.Address
}

// ListAddressesQuery contains the parameters for listing addresses.
type ListAddressesQuery struct {
	// WalletID is the ID of the wallet to query.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// AccountName is the name of the account to list addresses for.
	AccountName string

	// Scope is the key scope of the account.
	Scope KeyScope
}

// MarkAddressAsUsedParams contains the parameters for marking an address as
// used.
type MarkAddressAsUsedParams struct {
	// WalletID is the ID of the wallet containing the address.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// Address is the address to mark as used.
	Address btcutil.Address
}

// DerivationInfo contains the BIP-32 derivation path information for a key.
type DerivationInfo struct {
	// KeyScope is the key scope of the derivation path.
	KeyScope KeyScope

	// MasterKeyFingerprint is the fingerprint of the master key.
	MasterKeyFingerprint uint32

	// Account is the account number of the derivation path.
	Account uint32

	// Branch is the branch number of the derivation path (0 for external,
	// 1 for internal).
	Branch uint32

	// Index is the index of the key in the branch.
	Index uint32
}

// --------------------
// TxStore Types
// --------------------

// TxInfo represents the details of a transaction relevant to the wallet.
type TxInfo struct {
	// Hash is the transaction hash.
	Hash chainhash.Hash

	// SerializedTx is the serialized transaction.
	SerializedTx []byte

	// Received is the timestamp when the transaction was received.
	Received time.Time

	// Block contains metadata about the block that includes the
	// transaction. This will be nil for unmined (unconfirmed) transactions
	// and non-nil for mined (confirmed) transactions.
	Block *Block

	// Label is a user-defined label for the transaction.
	Label string
}

// CreateTxParams contains the parameters for creating a new transaction record.
type CreateTxParams struct {
	// WalletID is the ID of the wallet to create the transaction in.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// Tx is the transaction to record.
	Tx *wire.MsgTx

	// Label is an optional label for the transaction.
	Label string

	// Credits lists the outputs of the transaction that are controlled by
	// the wallet.
	Credits []CreditData
}

// CreditData contains the information needed to record a transaction credit.
// It acts as an explicit instruction to the CreateTx method, identifying which
// of the transaction's outputs belongs to the wallet and should be recorded as
// a new UTXO. This serves as a performance optimization, preventing the
// database layer from needing to parse every transaction output and query the
// address manager to determine ownership.
type CreditData struct {
	// Index is the output index of the credit.
	Index uint32

	// Address is the address that received the credit.
	Address btcutil.Address
}

// UpdateTxParams contains the parameters for updating a transaction record.
// Fields are pointers to allow for partial updates.
type UpdateTxParams struct {
	// WalletID is the ID of the wallet containing the transaction.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// Txid is the hash of the transaction to update.
	Txid chainhash.Hash

	// Block is the new block metadata for the transaction.
	Block *Block

	// Label is the new label for the transaction.
	Label *string
}

// GetTxQuery contains the parameters for querying a transaction. While a
// transaction hash (TxHash) is globally unique on the blockchain, the WalletID
// is necessary to retrieve wallet-specific metadata (e.g., labels, credits,
// debits) associated with that transaction. In a multi-wallet database, the
// same transaction might be relevant to multiple wallets, but its context
// (e.g., whether it's a credit or debit, and any custom labels) will differ
// for each wallet. The WalletID ensures the query returns the transaction's
// details from the correct wallet's perspective.
type GetTxQuery struct {
	// WalletID is the ID of the wallet to query.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// Txid is the hash of the transaction to query.
	Txid chainhash.Hash
}

// ListTxnsQuery contains the parameters for listing transactions.
type ListTxnsQuery struct {
	// WalletID is the ID of the wallet to query.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// StartHeight is the starting block height for the query.
	StartHeight uint32

	// EndHeight is the ending block height for the query.
	EndHeight uint32

	// UnminedOnly, if true, will return only unmined (unconfirmed)
	// transactions. If this is set, StartHeight and EndHeight will be
	// ignored.
	UnminedOnly bool
}

// DeleteTxParams contains the parameters for the DeleteTx method.
type DeleteTxParams struct {
	// WalletID is the ID of the wallet containing the transaction.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// Txid is the hash of the transaction to delete.
	Txid chainhash.Hash
}

// --------------------
// UTXOStore Types
// --------------------

// UtxoInfo represents an unspent transaction output (UTXO).
type UtxoInfo struct {
	// OutPoint is the outpoint of the UTXO.
	OutPoint wire.OutPoint

	// Amount is the value of the UTXO.
	Amount btcutil.Amount

	// PkScript is the public key script of the UTXO.
	PkScript []byte

	// Received is the timestamp when the UTXO was received.
	Received time.Time

	// FromCoinBase indicates whether the UTXO is from a coinbase
	// transaction.
	FromCoinBase bool

	// Height is the block height of the UTXO.
	Height uint32
}

// GetUtxoQuery contains the parameters for querying a UTXO.
type GetUtxoQuery struct {
	// WalletID is the ID of the wallet to query.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// OutPoint is the outpoint of the UTXO to query.
	OutPoint wire.OutPoint
}

// ListUtxosQuery holds the set of options for a ListUTXOs query.
type ListUtxosQuery struct {
	// WalletID is the ID of the wallet to query.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// Account is an optional filter to list UTXOs only for a specific
	// account.
	Account *uint32

	// MinConfs is the minimum number of confirmations for a UTXO to be
	// included.
	MinConfs int32

	// MaxConfs is the maximum number of confirmations for a UTXO to be
	// included.
	MaxConfs int32
}

// LeaseOutputParams contains the parameters for leasing a UTXO.
type LeaseOutputParams struct {
	// WalletID is the ID of the wallet containing the UTXO.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// ID is the lock ID for the UTXO.
	ID [32]byte

	// OutPoint is the outpoint of the UTXO to lock.
	OutPoint wire.OutPoint

	// Duration is the duration to lock the UTXO for.
	Duration time.Duration
}

// ReleaseOutputParams contains the parameters for releasing a UTXO lease.
type ReleaseOutputParams struct {
	// WalletID is the ID of the wallet containing the UTXO.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// ID is the lock ID of the UTXO to unlock.
	ID [32]byte

	// OutPoint is the outpoint of the UTXO to unlock.
	OutPoint wire.OutPoint
}

// LeasedOutput represents a UTXO that is currently locked.
type LeasedOutput struct {
	// OutPoint is the outpoint of the locked UTXO.
	OutPoint wire.OutPoint

	// LockID is the ID of the lock.
	LockID LockID

	// Expiration is the time when the lock expires.
	Expiration time.Time
}

// BalanceParams contains the parameters for the Balance method.
type BalanceParams struct {
	// WalletID is the ID of the wallet to query.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// MinConfirms is the minimum number of confirmations a UTXO must have
	// to be included in the balance calculation.
	MinConfirms int32
}

// LockID represents a unique context-specific ID assigned to an output lock.
type LockID [32]byte
