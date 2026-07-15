package waddrmgr

import (
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
)

// ManagerState contains the durable root address-manager state.
type ManagerState struct {
	Version                  uint32
	CreatedAt                time.Time
	WatchOnly                bool
	MasterPubParams          []byte
	MasterPrivParams         []byte
	EncryptedCryptoPubKey    []byte
	EncryptedCryptoPrivKey   []byte
	EncryptedCryptoScriptKey []byte
	EncryptedMasterHDPubKey  []byte
	EncryptedMasterHDPrivKey []byte
}

// SyncState contains the durable address-manager chain position.
type SyncState struct {
	StartBlock            BlockStamp
	SyncedTo              BlockStamp
	Birthday              time.Time
	BirthdayBlock         *BlockStamp
	BirthdayBlockVerified bool
}

// KeyScopeState contains the durable state for one key scope.
type KeyScopeState struct {
	Scope                KeyScope
	AddrSchema           ScopeAddrSchema
	EncryptedCoinPubKey  []byte
	EncryptedCoinPrivKey []byte
	LastAccount          uint32
}

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
	Scope                KeyScope
	Account              uint32
	Type                 AccountType
	Name                 string
	EncryptedPubKey      []byte
	EncryptedPrivKey     []byte
	MasterKeyFingerprint uint32
	NextExternalIndex    uint32
	NextInternalIndex    uint32
	AddrSchema           *ScopeAddrSchema
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
	Scope            KeyScope
	Hash             []byte
	Account          uint32
	Type             StoreAddressType
	AddedAt          time.Time
	SyncStatus       AddressSyncStatus
	Branch           *uint32
	Index            *uint32
	EncryptedPubKey  []byte
	EncryptedPrivKey []byte
	EncryptedHash    []byte
	EncryptedScript  []byte
	WitnessVersion   *uint8
	IsSecretScript   *bool
	Used             bool
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
