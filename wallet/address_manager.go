// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// ErrUnknownAddrType is an error returned when a wallet function is
	// called with an unknown address type.
	ErrUnknownAddrType = errors.New("unknown address type")

	// ErrImportedAccountNoAddrGen is an error returned when a new address
	// is requested for the default imported account within the wallet.
	ErrImportedAccountNoAddrGen = errors.New("addresses cannot be " +
		"generated for the default imported account")

	// ErrNotPubKeyAddress is an error returned when a function requires a
	// public key address, but a different type of address is provided.
	ErrNotPubKeyAddress = errors.New(
		"address is not a p2wkh or np2wkh address",
	)

	// errStopIteration is a special error used to stop the iteration in
	// ForEachAccountAddress.
	errStopIteration = errors.New("stop iteration")
)

// AddressProperty represents an address and its balance.
type AddressProperty struct {
	// Address is the address.
	Address btcutil.Address

	// Balance is the total unspent balance of the address, including both
	// confirmed and unconfirmed funds.
	Balance btcutil.Amount
}

// AddressManager provides an interface for generating and inspecting wallet
// addresses and scripts.
type AddressManager interface {
	// NewAddress returns a new address for the given account and address
	// type.
	//
	// NOTE: This method should be used with caution. Unlike
	// GetUnusedAddress, it does not scan for previously derived but unused
	// addresses. Using this method repeatedly can create gaps in the
	// address chain, which may negatively impact wallet recovery under
	// BIP44. It is primarily intended for advanced use cases such as bulk
	// address generation.
	NewAddress(ctx context.Context, accountName string,
		addrType waddrmgr.AddressType,
		change bool) (btcutil.Address, error)

	// GetUnusedAddress returns the first, oldest, unused address by
	// scanning forward from the start of the derivation path. This method
	// is the recommended default for obtaining a new receiving address, as
	// it prevents address reuse and avoids creating gaps in the address
	// chain that could impact wallet recovery.
	GetUnusedAddress(ctx context.Context, accountName string,
		addrType waddrmgr.AddressType, change bool) (
		btcutil.Address, error)

	// AddressInfo returns detailed information about a managed address. If
	// the address is not known to the wallet, an error is returned.
	AddressInfo(ctx context.Context,
		a btcutil.Address) (waddrmgr.ManagedAddress, error)

	// ListAddresses lists all addresses for a given account, including
	// their balances.
	ListAddresses(ctx context.Context, accountName string,
		addrType waddrmgr.AddressType) ([]AddressProperty, error)

	// ImportPublicKey imports a single public key as a watch-only address.
	ImportPublicKey(ctx context.Context, pubKey *btcec.PublicKey,
		addrType waddrmgr.AddressType) error

	// ImportTaprootScript imports a taproot script for tracking and
	// spending.
	ImportTaprootScript(ctx context.Context,
		tapscript waddrmgr.Tapscript) (waddrmgr.ManagedAddress, error)

	// ScriptForOutput returns the address, witness program, and redeem
	// script for a given UTXO.
	ScriptForOutput(ctx context.Context, output wire.TxOut) (
		waddrmgr.ManagedPubKeyAddress, []byte, []byte, error)
}

// TODO(yy): The current implementation of NewAddress has several architectural
// issues that should be addressed:
//
//  1. **Lack of Separation of Concerns:** The method tightly couples the
//     database logic with the address generation and chain backend
//     notification logic. The `waddrmgr` package currently handles both
//     derivation and persistence within a single database transaction, which
//     makes the transaction larger and longer than necessary.
//
// 2. **Incorrect Ordering of Operations:** The current flow is:
//  1. Create DB transaction.
//  2. Derive address.
//  3. Save address to DB.
//  4. Commit DB transaction.
//  5. Notify the chain backend to watch the new address.
//     This creates a potential race condition. If the program crashes after
//     committing the address to the database but before successfully
//     notifying the chain backend, the wallet will own an address that the
//     backend is not aware of. This could lead to a permanent loss of funds
//     if coins are sent to that address.
//
// Refactoring Plan:
//   - **Decouple `waddrmgr`:** The `waddrmgr` package should be refactored to
//     separate its concerns. It should provide:
//   - A pure, stateless function to derive an address from account info.
//   - A simple method to persist a newly derived address to the database.
//   - **Improve Operation Ordering in `wallet`:** The `NewAddress` method in
//     the `wallet` package should be updated to follow a more robust
//     sequence:
//     1. Start a DB transaction to read the required account information.
//     2. Use the pure derivation function from `waddrmgr` to generate the
//     new address *outside* of any DB transaction.
//     3. Notify the chain backend to watch the new address.
//     4. If the notification is successful, start a *second*, short-lived DB
//     transaction to persist the new address.
//     This ensures that we only save an address after we are confident that
//     it is being watched by the backend, preventing fund loss.
func (w *Wallet) NewAddress(_ context.Context, accountName string,
	addrType waddrmgr.AddressType, change bool) (btcutil.Address, error) {

	// Addresses cannot be derived from the catch-all imported accounts.
	if accountName == waddrmgr.ImportedAddrAccountName {
		return nil, ErrImportedAccountNoAddrGen
	}

	keyScope, err := w.keyScopeFromAddrType(addrType)
	if err != nil {
		return nil, err
	}

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	manager, err := w.addrStore.FetchScopedKeyManager(keyScope)
	if err != nil {
		return nil, err
	}

	addr, err := w.newAddress(manager, accountName, change)
	if err != nil {
		return nil, err
	}

	// Notify the rpc server about the newly created address.
	err = chainClient.NotifyReceived([]btcutil.Address{addr})
	if err != nil {
		return nil, err
	}

	return addr, nil
}

// keyScopeFromAddrType determines the appropriate key scope for a given
// address type.
//
// NOTE: While it may seem intuitive to iterate over the waddrmgr.ScopeAddrMap
// to act as a single source of truth, doing so is unsafe. The map contains
// ambiguities where a single address type, such as waddrmgr.WitnessPubKey, can
// map to multiple key scopes (e.g., KeyScopeBIP0084 and
// KeyScopeBIP0049Plus). Because map iteration in Go is non-deterministic, this
// would lead to unpredictable behavior. The switch statement is used here
// intentionally to enforce a clear, deterministic policy, ensuring that
// ambiguous types always resolve to their preferred, modern key scope.
func (w *Wallet) keyScopeFromAddrType(
	addrType waddrmgr.AddressType) (waddrmgr.KeyScope, error) {

	// Map the requested address type to its key scope.
	var addrKeyScope waddrmgr.KeyScope
	switch addrType {
	case waddrmgr.PubKeyHash:
		addrKeyScope = waddrmgr.KeyScopeBIP0044

	case waddrmgr.WitnessPubKey:
		addrKeyScope = waddrmgr.KeyScopeBIP0084

	case waddrmgr.NestedWitnessPubKey:
		addrKeyScope = waddrmgr.KeyScopeBIP0049Plus

	case waddrmgr.TaprootPubKey:
		addrKeyScope = waddrmgr.KeyScopeBIP0086

	// The following address types are not supported by this function as
	// they are not derived from a single public key using a key scope.
	// They are typically imported or involve more complex script-based
	// constructions.
	case waddrmgr.Script, waddrmgr.RawPubKey,
		waddrmgr.WitnessScript, waddrmgr.TaprootScript:
		return waddrmgr.KeyScope{}, fmt.Errorf("%w: %v",
			ErrUnknownAddrType, addrType)
	default:
		return waddrmgr.KeyScope{}, fmt.Errorf("%w: %v",
			ErrUnknownAddrType, addrType)
	}

	return addrKeyScope, nil
}

// newAddress returns the next external chained address for a wallet. It
// wraps the database transaction and the call to the scoped key manager's
// NewAddress method. A mutex is used to protect the in-memory state of the
// address manager from concurrent access during address creation.
func (w *Wallet) newAddress(manager *waddrmgr.ScopedKeyManager,
	accountName string, change bool) (btcutil.Address, error) {

	// The address manager uses OnCommit on the walletdb tx to update the
	// in-memory state of the account state. But because the commit happens
	// _after_ the account manager internal lock has been released, there
	// is a chance for the address index to be accessed concurrently, even
	// though the closure in OnCommit re-acquires the lock. To avoid this
	// issue, we surround the whole address creation process with a lock.
	//
	// TODO(yy): remove the lock - we should separate the db action and
	// memory cache.
	w.newAddrMtx.Lock()
	defer w.newAddrMtx.Unlock()

	var (
		addr btcutil.Address
		err  error
	)

	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		addr, err = manager.NewAddress(addrmgrNs, accountName, change)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return addr, nil
}

// GetUnusedAddress returns the first, oldest, unused address by scanning
// forward from the start of the derivation path. The address is considered
// "unused" if it has never appeared in a transaction. This method is the
// recommended default for obtaining a new receiving address. It prevents
// address reuse and avoids creating gaps in the address chain, which is
// critical for reliable wallet recovery under standards like BIP44 that
// enforce a gap limit of 20 unused addresses. If all previously derived
// addresses have been used, this method will delegate to NewAddress to
// generate a new one.
//
// TODO(yy): The current implementation of GetUnusedAddress is inefficient for
// wallets with a large number of used addresses. It iterates from the first
// address (index 0) forward until it finds an unused one, resulting in an O(n)
// complexity where n is the number of used addresses.
//
// A potential optimization of scanning backwards from the last derived address
// is UNSAFE. While faster in the common case, it can create gaps in the
// address chain. For example, if addresses [0, 1, 3] are used but [2] is not,
// a backward scan would return a new address after 3, leaving 2 as a gap.
// This violates the BIP44 gap limit (typically 20) and can lead to fund loss
// upon wallet recovery from seed, as the recovery process would stop scanning
// at the gap.
//
// The correct optimization is to persist a "first unused address pointer"
// (e.g., `firstUnusedExternalIndex`) for each account in the database.
//
// This would change the logic to:
//  1. `GetUnusedAddress`: Becomes an O(1) lookup. It reads the index from the
//     database and derives the address at that index.
//  2. `MarkUsed`: When an address is marked as used, if its index matches the
//     stored pointer, a one-time forward scan is performed to find the next
//     unused address, and the pointer is updated in the database.
//
// This moves the expensive scan from the frequent "read" operation to the less
// frequent "write" operation, providing both performance and safety.
func (w *Wallet) GetUnusedAddress(ctx context.Context, accountName string,
	addrType waddrmgr.AddressType, change bool) (btcutil.Address, error) {

	if accountName == waddrmgr.ImportedAddrAccountName {
		return nil, ErrImportedAccountNoAddrGen
	}

	keyScope, err := w.keyScopeFromAddrType(addrType)
	if err != nil {
		return nil, err
	}

	manager, err := w.addrStore.FetchScopedKeyManager(keyScope)
	if err != nil {
		return nil, err
	}

	var unusedAddr btcutil.Address

	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		// First, look up the account number for the passed account
		// name.
		acctNum, err := manager.LookupAccount(addrmgrNs, accountName)
		if err != nil {
			return err
		}

		// Now, iterate through all addresses for the account and
		// return the first one that is unused.
		return manager.ForEachAccountAddress(
			addrmgrNs, acctNum,
			func(maddr waddrmgr.ManagedAddress) error {
				// We only want to consider addresses that match
				// the change parameter.
				if maddr.Internal() != change {
					return nil
				}

				if !maddr.Used(addrmgrNs) {
					unusedAddr = maddr.Address()

					// Return a special error to signal
					// that the iteration should be
					// stopped. This is the idiomatic way
					// to halt a ForEach* loop in this
					// codebase.
					return errStopIteration
				}

				return nil
			},
		)
	})

	// We'll ignore the special error that we use to stop the iteration.
	if err != nil && !errors.Is(err, errStopIteration) {
		return nil, err
	}

	// If we found an unused address, we can return it now.
	if unusedAddr != nil {
		return unusedAddr, nil
	}

	// Otherwise, we'll generate a new one.
	return w.NewAddress(ctx, accountName, addrType, change)
}

// AddressInfo returns detailed information regarding a wallet address.
//
// This method provides metadata about a managed address, such as its type,
// derivation path, and whether it's internal or compressed.
//
// How it works:
// The method performs a direct lookup in the address manager to find the
// requested address.
//
// Logical Steps:
//  1. Initiate a read-only database transaction.
//  2. Call the underlying address manager's `Address` method to look up the
//     address.
//  3. Return the managed address information.
//
// Database Actions:
//   - This method performs a single read-only database transaction
//     (`walletdb.View`).
//   - It reads from the `waddrmgr` namespace to find the address.
//
// Time Complexity:
//   - The operation is a direct database lookup, making its complexity roughly
//     O(1) or O(log N) depending on the database backend's indexing strategy
//     for addresses. It is a very fast operation.
func (w *Wallet) AddressInfo(_ context.Context,
	a btcutil.Address) (waddrmgr.ManagedAddress, error) {

	var (
		managedAddress waddrmgr.ManagedAddress
		err            error
	)

	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		managedAddress, err = w.addrStore.Address(addrmgrNs, a)

		return err
	})

	return managedAddress, err
}

// ListAddresses lists all addresses for a given account, including their
// balances.
//
// This method provides a comprehensive view of all addresses within a
// specific account, along with their current confirmed balances.
//
// How it works:
// The method first calculates the balances of all UTXOs in the wallet and
// stores them in a map. It then iterates through all addresses of the
// specified account and looks up their balance in the map.
//
// Logical Steps:
//  1. Initiate a read-only database transaction.
//  2. Create a map to store address balances.
//  3. Iterate through all unspent transaction outputs (UTXOs) in the
//     wallet's `wtxmgr` namespace.
//  4. For each UTXO, extract the address and add the output's value to the
//     address's balance in the map.
//  5. Fetch the scoped key manager for the given address type.
//  6. Look up the account number for the given account name.
//  7. Iterate through all addresses in that account.
//  8. For each address, create an `AddressProperty` with the address and its
//     balance from the map.
//  9. Return the list of `AddressProperty` objects.
//
// Database Actions:
//   - This method performs a single read-only database transaction
//     (`walletdb.View`).
//   - It reads from both the `wtxmgr` and `waddrmgr` namespaces.
//
// Time Complexity:
//   - The complexity is O(U + A), where U is the number of unspent
//     transaction outputs in the wallet and A is the number of addresses in
//     the specified account. This is because it iterates through all UTXOs to
//     build the balance map and then iterates through all account addresses.
func (w *Wallet) ListAddresses(_ context.Context, accountName string,
	addrType waddrmgr.AddressType) ([]AddressProperty, error) {

	var properties []AddressProperty

	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		// First, we'll create a map of address to balance by iterating
		// through all the unspent outputs.
		addrToBalance := make(map[string]btcutil.Amount)

		utxos, err := w.txStore.UnspentOutputs(txmgrNs)
		if err != nil {
			return err
		}

		for _, utxo := range utxos {
			addr := extractAddrFromPKScript(
				utxo.PkScript, w.chainParams,
			)
			if addr == nil {
				continue
			}

			addrToBalance[addr.String()] += utxo.Amount
		}

		keyScope, err := w.keyScopeFromAddrType(addrType)
		if err != nil {
			return err
		}

		manager, err := w.addrStore.FetchScopedKeyManager(keyScope)
		if err != nil {
			return err
		}

		acctNum, err := manager.LookupAccount(addrmgrNs, accountName)
		if err != nil {
			return err
		}

		return manager.ForEachAccountAddress(addrmgrNs, acctNum,
			func(maddr waddrmgr.ManagedAddress) error {
				addr := maddr.Address()
				properties = append(properties, AddressProperty{
					Address: addr,
					Balance: addrToBalance[addr.String()],
				})

				return nil
			})
	})
	if err != nil {
		return nil, err
	}

	return properties, nil
}

