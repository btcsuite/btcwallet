// Package db provides a database-agnostic interface for wallet data storage,
// defining the core data types and store interfaces for wallets, accounts,
// addresses, transactions, and UTXOs.
package db

import (
	"math"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
)

const (
	// UnminedHeight is a sentinel value used in UtxoInfo.Height to indicate
	// that the UTXO is unconfirmed.
	//
	// Database rows represent an unconfirmed creating transaction by setting
	// `transactions.block_height` to NULL. The store layer maps that NULL to
	// this sentinel value so callers can continue to treat UtxoInfo.Height
	// as a non-nullable `uint32`.
	//
	// NOTE: This value must never overlap with a real block height.
	UnminedHeight uint32 = math.MaxUint32
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
//
// The enum values MUST match the IDs in the address_types database table.
// See migration 000003_address_types for the canonical descriptions.
type AddressType uint8

const (
	// RawPubKey represents a pay-to-pubkey (P2PK) address.
	RawPubKey AddressType = iota

	// PubKeyHash represents a pay-to-pubkey-hash (P2PKH) address.
	PubKeyHash

	// ScriptHash represents a pay-to-script-hash (P2SH) address.
	ScriptHash

	// NestedWitnessPubKey represents a P2WKH output nested within a P2SH
	// address.
	NestedWitnessPubKey

	// WitnessPubKey represents a pay-to-witness-pubkey-hash (P2WKH)
	// address.
	WitnessPubKey

	// WitnessScript represents a pay-to-witness-script-hash (P2WSH)
	// address.
	WitnessScript

	// TaprootPubKey represents a pay-to-taproot (P2TR) address.
	TaprootPubKey

	// Anchor represents a pay-to-anchor (P2A) address.
	Anchor
)

// AddressTypeInfo groups an address type identifier with its readable
// description.
type AddressTypeInfo struct {
	// Type is the AddressType value used as the unique identifier on both
	// the application side and the database side.
	Type AddressType

	// Description is a readable description of the address type.
	// It is intended for argument parsing, logging, and user-facing output.
	Description string
}

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

// AccountOrigin specifies the origin of an account. This is used to identify
// the account origin type, such as derived from the wallet's HD seed or
// imported from an external source.
//
// The enum values MUST match the IDs in the account_origins database table.
// See migration 000005_accounts for the canonical descriptions.
type AccountOrigin uint8

const (
	// DerivedAccount indicates the account was derived from a hierarchical
	// deterministic key.
	DerivedAccount AccountOrigin = iota

	// ImportedAccount indicates the account was imported from an external
	// source.
	ImportedAccount
)

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

	// ManagerVersion is the version of the wallet manager that created this
	// wallet.
	ManagerVersion int32

	// IsWatchOnly indicates whether the wallet is in watch-only mode,
	// meaning it does not have private keys and cannot sign transactions.
	IsWatchOnly bool

	// Birthday is the user-provided timestamp for when to start rescanning.
	// This is stored directly in the database and may be zero if not set.
	// If zero, means the wallet should be rescanned from the genesis block.
	Birthday time.Time

	// BirthdayBlock is the verified block reference for starting a rescan.
	// When this is non-nil, it indicates the block has been verified.
	// A nil value means the birthday block has not been set or verified.
	BirthdayBlock *Block

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

// ListWalletsQuery contains the parameters for listing wallets.
type ListWalletsQuery struct {
	// Page holds the pagination parameters for this query.
	Page page.Request[uint32]
}

// CreateWalletParams contains the parameters required to create a new wallet.
type CreateWalletParams struct {
	// Name is the name of the new wallet.
	Name string

	// IsImported should be set to true if the wallet is being created from
	// an existing seed.
	IsImported bool

	// ManagerVersion is the version of the wallet manager that created this
	// wallet.
	ManagerVersion int32

	// IsWatchOnly indicates whether the wallet is being created in
	// watch-only mode.
	IsWatchOnly bool

	// Birthday is the user-provided birthday timestamp for the wallet.
	// The zero value is treated as "no birthday" and is stored as NULL in
	// the database.
	Birthday time.Time

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

	// Birthday is the user-provided birthday timestamp for the wallet.
	// Setting this does NOT set BirthdayBlock.
	Birthday *time.Time

	// BirthdayBlock is the verified birthday block for the wallet.
	// When this is set, it indicates the block is already verified.
	BirthdayBlock *Block

	// SyncedTo is the new synchronization state for the wallet.
	SyncedTo *Block
}

// UpdateWalletSecretsParams contains the parameters for updating a wallet's
// secrets.
type UpdateWalletSecretsParams struct {
	// WalletID is the ID of the wallet to update.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// MasterPrivParams are the parameters (e.g. salt, scrypt N/R/P) used
	// to derive the master private key.
	MasterPrivParams []byte

	// EncryptedCryptoPrivKey is the encrypted private crypto key, used to
	// protect private keys in the database.
	EncryptedCryptoPrivKey []byte

	// EncryptedCryptoScriptKey is the encrypted script crypto key, used to
	// protect scripts in the database.
	EncryptedCryptoScriptKey []byte

	// EncryptedMasterHdPrivKey is the encrypted master HD private key.
	EncryptedMasterHdPrivKey []byte
}

// --------------------
// AccountStore Types
// --------------------

// AccountInfo contains all information about a single account, including its
// properties and balances.
type AccountInfo struct {
	// AccountNumber is the BIP44 account index used for derived accounts.
	// Imported accounts do not follow BIP44 derivation and therefore do not
	// have a meaningful account index. For those accounts, this field is
	// set to 0 and must not be used when Origin is ImportedAccount.
	AccountNumber uint32

	// AccountName is the human-readable name of the account.
	AccountName string

	// Origin indicates whether the account was derived from the wallet's
	// HD seed or imported from an external source.
	Origin AccountOrigin

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

	// CreatedAt is the timestamp when the account was created in the database.
	CreatedAt time.Time

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

// CreateDerivedAccountParams contains the parameters for creating a new derived
// account.
type CreateDerivedAccountParams struct {
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

// CreateImportedAccountParams contains the data required to store an imported
// account from an external extended key.
type CreateImportedAccountParams struct {
	// WalletID is the ID of the wallet to import the account into.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// Name is the name of the account to import.
	Name string

	// Scope is the key scope for the account. The address schema for the
	// scope will be determined by the default mapping for this scope.
	Scope KeyScope

	// MasterFingerprint is the fingerprint of the master key.
	MasterFingerprint uint32

	// EncryptedPublicKey is the encrypted extended public key for the
	// account. This should be encrypted by the caller before being passed
	// to the database layer.
	EncryptedPublicKey []byte

	// EncryptedPrivateKey is the encrypted extended private key for the
	// account. This should be encrypted by the caller before being passed
	// to the database layer. A nil or empty slice indicates watch-only.
	EncryptedPrivateKey []byte
}

// AccountProperties contains properties associated with each account, such as
// the account name, number, and the number of derived and imported keys.
type AccountProperties struct {
	// AccountNumber is the BIP44 account index used for derived accounts.
	// Imported accounts do not follow BIP44 derivation and therefore do not
	// have a meaningful account index. For those accounts, this field is
	// set to 0 and must not be used when Origin is ImportedAccount.
	AccountNumber uint32

	// AccountName is the user-identifying name of the account.
	AccountName string

	// Origin indicates whether the account was derived from the wallet's
	// HD seed or imported from an external source.
	Origin AccountOrigin

	// ExternalKeyCount is the number of internal keys that have been
	// derived for the account.
	ExternalKeyCount uint32

	// InternalKeyCount is the number of internal keys that have been
	// derived for the account.
	InternalKeyCount uint32

	// ImportedKeyCount is the number of imported keys found within the
	// account.
	ImportedKeyCount uint32

	// EncryptedPublicKey is the encrypted account public key. This is the
	// encrypted form of the extended public key that can be used to derive
	// addresses for the account. The caller must decrypt this using the
	// appropriate crypto key to use it.
	EncryptedPublicKey []byte

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

	// CreatedAt is the timestamp when the account was created in the database.
	CreatedAt time.Time

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
	// the account if AccountNumber is not provided. An empty string means
	// this field is not provided (use AccountNumber instead).
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
	// ID is the database unique identifier for the address.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	ID uint32

	// AccountID is the database unique identifier for the account this address
	// belongs to.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	AccountID uint32

	// AddrType is the type of address (P2PKH, P2WPKH, P2TR, etc.).
	AddrType AddressType

	// CreatedAt is when the address was created in the wallet database.
	CreatedAt time.Time

	// Origin indicates whether this is a derived HD address or an imported
	// address. Reuses the AccountOrigin enum.
	Origin AccountOrigin

	// Branch is the BIP44 branch number (0=external, 1=internal/change).
	// Zero value for imported addresses.
	Branch uint32

	// Index is the BIP44 index within the branch. Zero value for imported
	// addresses.
	Index uint32

	// ScriptPubKey is the script pubkey (plaintext).
	ScriptPubKey []byte

	// PubKey is the public key (plaintext). Zero value for derived
	// addresses.
	PubKey []byte

	// IsWatchOnly indicates whether the wallet has the private key for this
	// address. Convenience field.
	IsWatchOnly bool
}

// AddressSecret contains sensitive encrypted material for an address.
type AddressSecret struct {
	// AddressID is the database unique identifier for the address.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	AddressID uint32

	// EncryptedPrivKey is the encrypted private key.
	EncryptedPrivKey []byte

	// EncryptedScript is the encrypted redeem or witness script for
	// P2SH/P2WSH addresses. For Taproot, this is the TLV-encoded Tapscript.
	EncryptedScript []byte
}

// NewDerivedAddressParams contains the parameters for creating a new derived
// address.
type NewDerivedAddressParams struct {
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

// NewImportedAddressParams defines the input required to import a single
// address into the wallet. All imported addresses are assigned to the
// wallet imported account. The caller is responsible for encrypting any
// sensitive material before populating this struct.
type NewImportedAddressParams struct {
	// WalletID identifies the wallet that will own this address.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// Scope is the key scope for the imported address.
	Scope KeyScope

	// AddressType specifies the address format being imported, such as
	// P2PKH, P2WPKH, or P2TR.
	AddressType AddressType

	// ScriptPubKey contains the script pubkey associated with the address
	// (stored in plaintext).
	ScriptPubKey []byte

	// PubKey contains the public key corresponding to the private key for
	// this address (stored in plaintext).
	PubKey []byte

	// EncryptedPrivateKey contains the encrypted private key for the address.
	EncryptedPrivateKey []byte

	// EncryptedScript contains the encrypted, pre serialized script.
	// For P2SH and P2WSH this is the redeem or witness script.
	// For Taproot this is the TLV encoded Tapscript.
	EncryptedScript []byte
}

// GetAddressQuery contains the parameters for querying an address.
type GetAddressQuery struct {
	// WalletID is the ID of the wallet to query.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// ScriptPubKey is the script pubkey to be fetched.
	ScriptPubKey []byte
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

	// Page holds the pagination parameters for this query.
	Page page.Request[uint32]
}

// --------------------
// TxStore Types
// --------------------

// TxStatus represents the wallet-relative validity state of a transaction.
//
// The value is stored in the `transactions.status` column as a compact numeric
// code so hot-path predicates and indexes do not pay the storage/index cost of
// repeated status strings.
//
// The enum values MUST match the numeric codes enforced by migration
// `000007_transactions` in both Postgres and SQLite.
type TxStatus uint8

const (
	// TxStatusPending indicates a locally-created transaction that has not yet
	// been broadcast.
	//
	// Callers use this state when they need the store to retain a locally
	// authored transaction before network publication.
	TxStatusPending TxStatus = iota

	// TxStatusPublished indicates a transaction that is still considered
	// valid by the wallet and is either unconfirmed in the mempool or
	// confirmed in the current best chain.
	//
	// The two cases share one validity status because Block already tells the
	// caller whether the transaction is mined. Keeping both under
	// TxStatusPublished avoids contradictory combinations such as
	// "confirmed but not published" and keeps this field focused on whether the
	// wallet still treats the transaction as valid.
	TxStatusPublished

	// TxStatusReplaced indicates a transaction that was invalidated by a
	// competing transaction spending the same inputs via RBF.
	TxStatusReplaced

	// TxStatusFailed indicates a transaction that was invalidated by a
	// competing transaction spending the same inputs (double-spend).
	TxStatusFailed

	// TxStatusOrphaned indicates a coinbase transaction that was reorged out of
	// the best chain.
	//
	// This state is reserved for coinbase transactions. Non-coinbase rows must
	// use a different terminal state such as TxStatusFailed or
	// TxStatusReplaced.
	TxStatusOrphaned
)

// String returns the human-readable name of one transaction status code.
func (s TxStatus) String() string {
	switch s {
	case TxStatusPending:
		return "pending"

	case TxStatusPublished:
		return "published"

	case TxStatusReplaced:
		return "replaced"

	case TxStatusFailed:
		return "failed"

	case TxStatusOrphaned:
		return "orphaned"

	default:
		return "unknown"
	}
}

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

	// Status is the wallet-relative validity state of the transaction.
	//
	// For confirmed transactions, Status is always TxStatusPublished.
	Status TxStatus

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

	// Received is the timestamp when the wallet learned about the transaction.
	//
	// Callers supply this explicitly so import/recovery paths can preserve the
	// wallet-observed time instead of defaulting to insertion time.
	//
	// This timestamp is stored in the database as UTC.
	Received time.Time

	// Block optionally records the transaction as already confirmed in the
	// provided block. When nil, the transaction is treated as unmined.
	//
	// The Store layer records factual transaction state. A non-nil Block means
	// the caller is inserting a row already anchored to a specific block in
	// wallet history; it does not ask the Store layer to infer publishing or
	// confirmation policy on the caller's behalf.
	//
	// NOTE: Coinbase transactions cannot exist in the mempool. Callers MUST
	// provide a non-nil Block when recording coinbase transactions.
	Block *Block

	// Status is the initial wallet-relative validity state for the
	// transaction.
	//
	// This Store-layer API inserts an already-constructed transaction row. It
	// does not build, sign, publish, or infer higher-level wallet policy.
	// Callers must therefore set Status explicitly instead of asking the Store
	// to guess how an app-layer workflow intends to use the row.
	//
	// Unmined inserts choose between TxStatusPending and TxStatusPublished.
	// Confirmed inserts (Block non-nil) must use TxStatusPublished to satisfy
	// the transaction-state invariants. TxStatusOrphaned is reserved for
	// coinbase rows and must not be used for ordinary transactions.
	Status TxStatus

	// Label is an optional label for the transaction.
	Label string

	// Credits maps wallet-owned output indexes to their display addresses.
	//
	// The output index is the map key, so duplicate credited outputs are
	// impossible by construction.
	//
	// NOTE: The address value is for display only. The database layer still
	// matches ownership by the output's script_pub_key
	// (`params.Tx.TxOut[index].PkScript`), which is the canonical key
	// used by the address schema.
	Credits map[uint32]btcutil.Address
}

// UpdateTxState contains one requested transaction-state change.
type UpdateTxState struct {
	// Block records the transaction as confirmed in the provided block.
	//
	// Nil clears any current block assignment and returns the row to an unmined
	// state.
	Block *Block

	// Status is the wallet-relative transaction state to store together with
	// the requested block assignment.
	Status TxStatus
}

// UpdateTxParams contains the mutable fields that UpdateTx may patch.
type UpdateTxParams struct {
	// WalletID is the ID of the wallet containing the transaction.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// Txid is the hash of the transaction to update.
	Txid chainhash.Hash

	// Label optionally replaces the stored user-visible label.
	//
	// Nil leaves the label unchanged. The empty string is a valid value and
	// clears any prior label.
	Label *string

	// State optionally replaces the stored block/status view of the
	// transaction.
	//
	// Nil leaves the chain-state metadata unchanged.
	State *UpdateTxState
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

	// UnminedOnly, if true, switches ListTxns onto the dedicated no-confirming-
	// block read path.
	//
	// This path returns the active unmined set together with retained invalid
	// history rows that also no longer have a confirming block, such as
	// orphaned or failed transactions after rollback.
	//
	// This is not equivalent to using zero confirmations. The confirmed
	// height-range query cannot express "only rows with no block", so
	// StartHeight and EndHeight are ignored when this flag is set.
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
	//
	// Unconfirmed UTXOs use the sentinel value UnminedHeight.
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

	// Account is an optional BIP44 account-number filter.
	Account *uint32

	// MinConfs optionally requires each returned UTXO to have at least this
	// many confirmations.
	MinConfs *int32

	// MaxConfs optionally requires each returned UTXO to have at most this
	// many confirmations.
	MaxConfs *int32
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

// BalanceResult represents one wallet-scoped balance view after applying the
// requested filters.
type BalanceResult struct {
	// Total is the sum of every matching UTXO, including leased outputs.
	Total btcutil.Amount

	// Locked is the subset of Total currently covered by active output leases.
	Locked btcutil.Amount
}

// BalanceParams contains the parameters for the Balance method.
type BalanceParams struct {
	// WalletID is the ID of the wallet to query.
	//
	// NOTE: uint32 is used to ensure compatibility with standard SQL
	// databases (signed 64-bit integers).
	WalletID uint32

	// Account optionally restricts the balance to one BIP44 account number.
	Account *uint32

	// MinConfs optionally requires each counted output to have at least
	// this many confirmations.
	MinConfs *int32

	// MaxConfs optionally requires each counted output to have at most
	// this many confirmations.
	MaxConfs *int32

	// CoinbaseMaturity optionally requires coinbase outputs to have at
	// least this many confirmations before they count toward the returned
	// balance result. Non-coinbase outputs ignore this filter.
	CoinbaseMaturity *int32
}

// LockID represents a unique context-specific ID assigned to an output lock.
type LockID [32]byte
