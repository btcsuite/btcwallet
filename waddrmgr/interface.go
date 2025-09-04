// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr

import (
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/walletdb"
)

// TODO(yy) This file provides a set of interfaces that abstract the
// functionality of the waddrmgr package. The interfaces are designed to be
// composable, allowing for a clean separation of concerns and making it easier
// to test and maintain the codebase.
//
// The AddrStore interface is the top-level interface that composes all the
// other interfaces. It is responsible for managing its own database
// transactions, which means that the walletdb.ReadWriteBucket and
// walletdb.ReadBucket arguments are not present in the interface methods.
//
// The breakdown of the interfaces is as follows:
//
// ChainState: Manages the wallet's sync state with the blockchain.
// KeyScopeManager: Manages key scopes.
// AddressManager: Manages addresses.
// AccountManager: Manages accounts.
// CryptoManager: Manages the encrypted state of the wallet.
// WatchOnlyManager: Manages watch-only functionality.
//
// The current AddrStore interface has several design flaws that should be
// addressed in a future refactoring:
//
// 1. Leaky Abstraction & Lack of Encapsulation:
//    - Problem: Nearly every method in the interface requires the caller (the
//      `wallet` package) to pass in a `walletdb.ReadWriteBucket` or
//      `walletdb.ReadBucket`.
//    - Why it's an issue: This is a classic "leaky abstraction." The
//      `AddrStore` is supposed to abstract away the details of address
//      management, but it's forcing its consumer to know about and manage its
//      internal database structure and transactions. The `wallet` package
//      should not be responsible for starting a database transaction just to
//      call a method on the `AddrStore`. The `AddrStore` should manage its own
//      persistence internally.
//
// 2. Violation of the Interface Segregation Principle (ISP):
//    - Problem: The `AddrStore` is a "fat" interface. It includes dozens of
//      methods covering many distinct areas of responsibility: cryptographic
//      operations (`Lock`, `Unlock`), chain synchronization (`SyncedTo`), key
//      management (`NewScopedKeyManager`), and address lookups (`Address`).
//    - Why it's an issue: Consumers of the interface are forced to depend on
//      methods they don't use. For example, a component that only needs to
//      look up an address (`Address`) is also coupled to methods for changing
//      passphrases. This leads to unnecessary dependencies and makes the code
//      harder to test, as mocks become massive and unwieldy.
//
// 3. Violation of the Single Responsibility Principle (SRP):
//    - Problem: The interface combines multiple, distinct responsibilities
//      into one unit. It acts as a key manager, an address book, a crypto
//      manager, and a chain state tracker all at once.
//    - Why it's an issue: This makes the `AddrStore` difficult to reason about
//      and maintain. A change in how we manage chain state, for example, could
//      require modifying an interface that is also responsible for
//      cryptography. These concerns should be separate.

// AddrStore is an interface that describes a wallet address store.
//
//nolint:interfacebloat
type AddrStore interface {
	// Birthday returns the birthday of the address store.
	Birthday() time.Time

	// SetSyncedTo marks the address manager to be in sync with the
	// recently-seen block described by the blockstamp.
	SetSyncedTo(ns walletdb.ReadWriteBucket, bs *BlockStamp) error

	// SetBirthdayBlock sets the birthday block, or earliest time a key could
	// have been used, for the manager.
	SetBirthdayBlock(ns walletdb.ReadWriteBucket, block BlockStamp,
		verified bool) error

	// SyncedTo returns details about the block height and hash that the
	// address manager is synced through at the very least.
	SyncedTo() BlockStamp

	// BlockHash returns the block hash at a particular block height.
	BlockHash(ns walletdb.ReadBucket, height int32) (*chainhash.Hash, error)

	// ActiveScopedKeyManagers returns a slice of all the active scoped key
	// managers currently known by the root key manager.
	ActiveScopedKeyManagers() []*ScopedKeyManager

	// FetchScopedKeyManager attempts to fetch an active scoped manager
	// according to its registered scope.
	FetchScopedKeyManager(scope KeyScope) (*ScopedKeyManager, error)

	// Address returns a managed address given the passed address if it is
	// known to the address manager.
	Address(ns walletdb.ReadBucket,
		address btcutil.Address) (ManagedAddress, error)

	// AddrAccount returns the account to which the given address belongs.
	AddrAccount(ns walletdb.ReadBucket,
		address btcutil.Address) (*ScopedKeyManager, uint32, error)

	// ForEachRelevantActiveAddress invokes the given closure on each active
	// address relevant to the wallet.
	ForEachRelevantActiveAddress(ns walletdb.ReadBucket,
		fn func(addr btcutil.Address) error) error

	// Unlock derives the master private key from the specified passphrase.
	Unlock(ns walletdb.ReadBucket, passphrase []byte) error

	// Lock performs a best try effort to remove and zero all secret keys
	// associated with the address manager.
	Lock() error

	// IsLocked returns whether or not the address managed is locked.
	IsLocked() bool

	// ChangePassphrase changes either the public or private passphrase to
	// the provided value depending on the private flag.
	ChangePassphrase(ns walletdb.ReadWriteBucket, oldPass, newPass []byte,
		private bool, scryptOptions *ScryptOptions) error

	// WatchOnly returns true if the root manager is in watch only mode, and
	// false otherwise.
	WatchOnly() bool

	// MarkUsed updates the used flag for the provided address.
	MarkUsed(ns walletdb.ReadWriteBucket, address btcutil.Address) error

	// BirthdayBlock returns the birthday block of the address store.
	BirthdayBlock(ns walletdb.ReadBucket) (BlockStamp, bool, error)

	// IsWatchOnlyAccount determines if the account with the given key scope
	// is set up as watch-only.
	IsWatchOnlyAccount(ns walletdb.ReadBucket, keyScope KeyScope,
		account uint32) (bool, error)

	// NewScopedKeyManager creates a new scoped key manager from the root
	// manager.
	NewScopedKeyManager(ns walletdb.ReadWriteBucket,
		scope KeyScope, addrSchema ScopeAddrSchema) (*ScopedKeyManager, error)

	// SetBirthday sets the birthday of the address store.
	SetBirthday(ns walletdb.ReadWriteBucket, birthday time.Time) error

	// ForEachAccountAddress calls the given function with each address of
	// the given account stored in the manager, breaking early on error.
	ForEachAccountAddress(ns walletdb.ReadBucket, account uint32,
		fn func(maddr ManagedAddress) error) error

	// LookupAccount returns the corresponding key scope and account number
	// for the account with the given name.
	LookupAccount(ns walletdb.ReadBucket,
		name string) (KeyScope, uint32, error)

	// ForEachActiveAddress calls the given function with each active address
	// stored in the manager, breaking early on error.
	ForEachActiveAddress(ns walletdb.ReadBucket,
		fn func(addr btcutil.Address) error) error

	// ConvertToWatchingOnly converts the current address manager to a locked
	// watching-only address manager.
	ConvertToWatchingOnly(ns walletdb.ReadWriteBucket) error

	// ChainParams returns the chain parameters for this address manager.
	ChainParams() *chaincfg.Params

	// Close cleanly shuts down the manager.
	Close()
}
