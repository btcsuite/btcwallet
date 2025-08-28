// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
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
