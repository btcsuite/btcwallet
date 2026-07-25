package waddrmgr

import (
	"errors"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
)

var (
	// ErrStoreAddressTypeUnsupported reports an address encoding that the
	// store-backed manager cannot reconstruct safely.
	ErrStoreAddressTypeUnsupported = errors.New(
		"store-backed address type is unsupported",
	)
)

// ManagerState contains the durable root address-manager state.
type ManagerState struct {
	// Version is the address-manager schema version.
	Version uint32

	// CreatedAt is the manager creation time.
	CreatedAt time.Time

	// WatchOnly records whether the manager has private material.
	WatchOnly bool

	// MasterPubParams contains the serialized public passphrase parameters.
	MasterPubParams []byte

	// MasterPrivParams contains the serialized private passphrase parameters.
	MasterPrivParams []byte

	// EncryptedCryptoPubKey contains the encrypted public crypto key.
	EncryptedCryptoPubKey []byte

	// EncryptedCryptoPrivKey contains the encrypted private crypto key.
	EncryptedCryptoPrivKey []byte

	// EncryptedCryptoScriptKey contains the encrypted script crypto key.
	EncryptedCryptoScriptKey []byte

	// EncryptedMasterHDPubKey contains the encrypted master HD public key.
	EncryptedMasterHDPubKey []byte

	// EncryptedMasterHDPrivKey contains the encrypted master HD private key.
	EncryptedMasterHDPrivKey []byte
}

// SyncState contains the durable address-manager chain position.
type SyncState struct {
	// StartBlock is the earliest block relevant to the manager.
	StartBlock BlockStamp

	// SyncedTo is the latest block processed by the manager.
	SyncedTo BlockStamp

	// Birthday is the earliest possible key creation time.
	Birthday time.Time

	// BirthdayBlock is the block associated with the manager birthday.
	BirthdayBlock *BlockStamp

	// BirthdayBlockVerified records whether BirthdayBlock was verified.
	BirthdayBlockVerified bool
}

// KeyScopeState contains the durable state for one key scope.
type KeyScopeState struct {
	// Scope identifies the key derivation scope.
	Scope KeyScope

	// AddrSchema defines the scope's external and internal address types.
	AddrSchema ScopeAddrSchema

	// EncryptedCoinPubKey contains the encrypted coin-type public key.
	EncryptedCoinPubKey []byte

	// EncryptedCoinPrivKey contains the encrypted coin-type private key.
	EncryptedCoinPrivKey []byte

	// LastAccount is the last account allocated in the scope.
	LastAccount uint32
}

const (
	// NoAccount is the last-account sentinel for a scope that has not yet
	// allocated account zero.
	NoAccount = ^uint32(0)
)

// AccountType identifies a durable address-manager account encoding.
type AccountType uint8

const (
	// AccountDefault is a derived BIP0044-like account.
	AccountDefault AccountType = iota

	// AccountWatchOnly is an imported extended-public-key account.
	AccountWatchOnly
)

// AccountState contains the durable state for one scoped account.
type AccountState struct {
	// Scope identifies the account's key derivation scope.
	Scope KeyScope

	// Account is the account number within Scope.
	Account uint32

	// Type identifies how the account was created.
	Type AccountType

	// Name is the user-facing account name.
	Name string

	// EncryptedPubKey contains the encrypted account public key.
	EncryptedPubKey []byte

	// EncryptedPrivKey contains the encrypted account private key.
	EncryptedPrivKey []byte

	// MasterKeyFingerprint identifies the account's root key.
	MasterKeyFingerprint uint32

	// NextExternalIndex is the next external child index to allocate.
	NextExternalIndex uint32

	// NextInternalIndex is the next internal child index to allocate.
	NextInternalIndex uint32

	// AddrSchema optionally overrides the scope's address schema.
	AddrSchema *ScopeAddrSchema
}

// StoreAddressType identifies a durable address-manager address encoding.
type StoreAddressType uint8

const (
	// AddressChain is an HD-derived address.
	AddressChain StoreAddressType = iota

	// AddressImported is an imported public or private key.
	AddressImported

	// AddressScript is an imported legacy script.
	AddressScript

	// AddressWitnessScript is an imported witness-v0 script.
	AddressWitnessScript

	// AddressTaprootScript is an imported witness-v1 tapscript.
	AddressTaprootScript
)

// AddressSyncStatus identifies the persisted per-address sync state.
type AddressSyncStatus uint8

const (
	// AddressSyncNone has no per-address sync state.
	AddressSyncNone AddressSyncStatus = iota

	// AddressSyncPartial is reserved for a partially synchronized address.
	AddressSyncPartial

	// AddressSyncFull marks a fully synchronized address.
	AddressSyncFull
)

// AddressState contains the durable state for one managed address.
type AddressState struct {
	// Scope identifies the address's key derivation scope.
	Scope KeyScope

	// Hash is the durable digest of the address identifier.
	Hash []byte

	// Account is the address's account number.
	Account uint32

	// Type identifies how the address was created.
	Type StoreAddressType

	// AddedAt is the time the address was added to the manager.
	AddedAt time.Time

	// SyncStatus is the address's synchronization state.
	SyncStatus AddressSyncStatus

	// Branch is the optional HD derivation branch.
	Branch *uint32

	// Index is the optional HD derivation child index.
	Index *uint32

	// EncryptedPubKey contains encrypted imported public-key material.
	EncryptedPubKey []byte

	// EncryptedPrivKey contains encrypted imported private-key material.
	EncryptedPrivKey []byte

	// EncryptedHash contains an encrypted imported script identity.
	EncryptedHash []byte

	// EncryptedScript contains an encrypted imported script.
	EncryptedScript []byte

	// WitnessVersion identifies an imported witness script version.
	WitnessVersion *uint8

	// IsSecretScript records whether a script requires private encryption.
	IsSecretScript *bool

	// Used records whether the address has appeared on chain.
	Used bool
}

// ManagerReadStore exposes the complete durable waddrmgr read surface without
// exposing a walletdb bucket in each operation.
//
//nolint:interfacebloat // The interface mirrors one existing manager domain.
type ManagerReadStore interface {
	// ManagerState returns the durable root address-manager state.
	ManagerState() (ManagerState, error)

	// SyncState returns the durable address-manager chain position.
	SyncState() (SyncState, error)

	// BlockHash returns the block hash recorded at the given height.
	BlockHash(height int32) (*chainhash.Hash, error)

	// KeyScope returns the durable state for one key scope.
	KeyScope(scope KeyScope) (KeyScopeState, error)

	// KeyScopes returns every durable key scope in storage order.
	KeyScopes() ([]KeyScopeState, error)

	// Account returns one durable account in the given key scope.
	Account(scope KeyScope, account uint32) (AccountState, error)

	// AccountByName returns one durable account by its scoped name.
	AccountByName(scope KeyScope, name string) (AccountState, error)

	// Accounts returns every durable account in the given key scope.
	Accounts(scope KeyScope) ([]AccountState, error)

	// Address returns one durable address by its legacy identifier.
	Address(scope KeyScope, addressID []byte) (AddressState, error)

	// AccountAddresses returns every address belonging to one account.
	AccountAddresses(scope KeyScope, account uint32) ([]AddressState, error)

	// ActiveAddresses returns every active address in the given key scope.
	ActiveAddresses(scope KeyScope) ([]AddressState, error)
}

// ManagerReadWriteStore exposes the complete durable waddrmgr write surface
// without exposing a walletdb bucket in each operation.
//
//nolint:interfacebloat // The interface mirrors one existing manager domain.
type ManagerReadWriteStore interface {
	// ManagerReadStore provides the complete manager read surface.
	ManagerReadStore

	// PutManagerState replaces the durable root address-manager state.
	PutManagerState(state ManagerState) error

	// PutSyncState replaces the complete durable chain position.
	PutSyncState(state SyncState) error

	// SetSyncedTo marks the address manager as synced through the block.
	SetSyncedTo(block *BlockStamp) error

	// SetBirthday replaces the wallet birthday timestamp.
	SetBirthday(birthday time.Time) error

	// SetBirthdayBlock sets or clears the wallet birthday block.
	SetBirthdayBlock(block *BlockStamp) error

	// SetBirthdayBlockVerified records birthday-block verification state.
	SetBirthdayBlockVerified(verified bool) error

	// PutKeyScope creates or replaces one durable key-scope state.
	PutKeyScope(state KeyScopeState) error

	// SetCoinTypeKeys replaces the encrypted coin-type keys for a scope.
	SetCoinTypeKeys(scope KeyScope, encryptedPub,
		encryptedPriv []byte) error

	// SetLastAccount records the last allocated account for a key scope.
	SetLastAccount(scope KeyScope, account uint32) error

	// PutAccount creates or replaces one durable scoped account.
	PutAccount(state AccountState) error

	// RenameAccount replaces the name of one durable scoped account.
	RenameAccount(scope KeyScope, account uint32, name string) error

	// SetAccountIndexes replaces an account's next derivation indexes.
	SetAccountIndexes(scope KeyScope, account, nextExternal,
		nextInternal uint32) error

	// PutAddress creates or replaces one durable managed address.
	PutAddress(addressID []byte, state AddressState) error

	// MarkAddressUsed records that one managed address has been used.
	MarkAddressUsed(scope KeyScope, addressID []byte) error

	// DeletePrivateKeys removes all persisted private key material.
	DeletePrivateKeys() error
}

// ManagerReadWriteTx extends a writable manager store with a callback that is
// invoked only after its enclosing transaction commits successfully.
type ManagerReadWriteTx interface {
	// ManagerReadWriteStore provides the manager read/write surface.
	ManagerReadWriteStore

	// OnCommit registers a callback for successful transaction commit.
	OnCommit(func())
}
