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
)

// AddressProperty represents an address and its balance.
type AddressProperty struct {
	Address btcutil.Address
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

	// GetUnusedAddress returns the first, oldest, unused address by scanning
	// forward from the start of the derivation path. This method is the
	// recommended default for obtaining a new receiving address, as it
	// prevents address reuse and avoids creating gaps in the address chain
	// that could impact wallet recovery.
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
//
// NewAddress returns a new address for the given account and address type.
// This method is a low-level primitive that will always derive a new, unused
// address from the end of the address chain.
//
// It returns the next external or internal address for the wallet dictated by
// the value of the `change` parameter. If change is true, then an internal
// address will be returned, otherwise an external address should be returned.
// The account parameter is the name of the account from which the address
// should be generated. The addrType parameter specifies the type of address to
// be generated.
//
// NOTE: This method should be used with caution. Unlike GetUnusedAddress, it
// does not scan for previously derived but unused addresses. Using this method
// repeatedly can create gaps in the address chain. If a gap of 20 consecutive
// unused addresses is created, wallet recovery from seed may fail under BIP44.
// It is primarily intended for advanced use cases such as bulk address
// generation. For most applications, GetUnusedAddress is the recommended
// method for obtaining a receiving address.
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
// address type. This function maps a high-level address type (like P2WKH,
// NP2WKH, P2TR) to the corresponding low-level BIP-defined key scope used for
// derivation.
func (w *Wallet) keyScopeFromAddrType(
	addrType waddrmgr.AddressType) (waddrmgr.KeyScope, error) {

	// Map the requested address type to its key scope.
	var addrKeyScope waddrmgr.KeyScope
	switch addrType {
	case waddrmgr.WitnessPubKey:
		addrKeyScope = waddrmgr.KeyScopeBIP0084
	case waddrmgr.NestedWitnessPubKey:
		addrKeyScope = waddrmgr.KeyScopeBIP0049Plus
	case waddrmgr.TaprootPubKey:
		addrKeyScope = waddrmgr.KeyScopeBIP0086
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
