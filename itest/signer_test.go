// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build itest

package itest

import (
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// testSignerDerivePubKey verifies the exported selector-bearing Signer
// contract can derive a public key without wallet-internal database types.
func testSignerDerivePubKey(h *bwtest.HarnessTest) {
	// Arrange: Use the harness-owned lifecycle and address fixture to create a
	// real started wallet with its default BIP84 account. The fixture restores
	// the wallet's locked state before the Signer request is constructed.
	w, _ := h.NewWallet(bwtest.WalletFixture{})
	h.NewWalletAddressOfType(w, waddrmgr.WitnessPubKey)
	params := wallet.DerivePubKeyParams{
		Account: wallet.NewAccountSelectorByName(
			waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountName,
		),
		Branch: 0,
		Index:  7,
	}

	var signer wallet.Signer = w

	// Act: Invoke public derivation through the imported Signer interface so
	// this integration package compiles against the caller-facing request.
	pubKey, err := signer.DerivePubKey(h.Context(), params)

	// Assert: A locked wallet can return the requested public child without
	// any backend identifier or private signing access in the request.
	require.NoError(h, err)
	require.NotNil(h, pubKey)
}
