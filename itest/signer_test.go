// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build itest

package itest

import (
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// signerScope is the key scope the derivation cases operate in. Its default
// account is materialized by deriving an address of the matching type.
var signerScope = waddrmgr.KeyScopeBIP0084

// signerAddrType is the address type whose key scope is signerScope.
const signerAddrType = waddrmgr.WitnessPubKey

// testSignerDerivePubKeyPaths verifies that public derivation resolves the
// same account under either exported selector and returns exactly the child
// the account's own extended public key defines.
func testSignerDerivePubKeyPaths(h *bwtest.HarnessTest) {
	// Arrange: A started, locked wallet whose default account has issued one
	// external address. The account's extended public key is public metadata,
	// so the expected children can be derived here without any store or
	// private-key read.
	ctx := h.Context()
	w, _ := h.NewWallet(bwtest.WalletFixture{})
	firstAddr := h.NewWalletAddressOfType(w, signerAddrType)

	account, err := w.GetAccount(ctx, signerScope, waddrmgr.DefaultAccountName)
	require.NoError(h, err, "failed to read the default account")

	accountKey, err := hdkeychain.NewKeyFromString(string(account.PublicKey))
	require.NoError(h, err, "failed to parse the account public key")

	// Derive through the imported Signer interface rather than the concrete
	// wallet, so this package proves a caller can hold the public interface
	// and build its request from exported types alone.
	var signer wallet.Signer = w

	paths := []struct {
		name   string
		branch uint32
		index  uint32
	}{
		{name: "external first", branch: 0, index: 0},
		{name: "external later", branch: 0, index: 7},
		{name: "internal first", branch: 1, index: 0},
		{name: "internal later", branch: 1, index: 3},

		// The largest unhardened branch and index. A BIP32 child index
		// is a uint32, but the half at HardenedKeyStart and above is
		// the hardened encoding: index i there names child
		// i-HardenedKeyStart derived from the parent private key. An
		// account extended public key cannot reach that half at all,
		// and BIP44 keeps change and address_index unhardened, so the
		// ceiling is 2^31 children per branch rather than 2^32.
		//
		// testSignerDerivePubKeyRejectRequest asserts the first value
		// above the boundary is refused, so these are its accepted
		// maxima.
		{
			name:   "branch maximum",
			branch: hdkeychain.HardenedKeyStart - 1,
			index:  0,
		},
		{
			name:   "index maximum",
			branch: 0,
			index:  hdkeychain.HardenedKeyStart - 1,
		},
	}

	for _, path := range paths {
		branchKey, err := accountKey.Derive(path.branch)
		require.NoError(h, err, "failed to derive branch %d", path.branch)

		childKey, err := branchKey.Derive(path.index)
		require.NoError(h, err, "failed to derive index %d", path.index)

		want, err := childKey.ECPubKey()
		require.NoError(h, err, "failed to convert %s", path.name)

		// Act: Derive the same child through both exported selectors.
		byName, err := signer.DerivePubKey(ctx, wallet.DerivePubKeyParams{
			Account: wallet.NewAccountSelectorByName(
				signerScope, waddrmgr.DefaultAccountName,
			),
			Branch: path.branch,
			Index:  path.index,
		})
		require.NoError(h, err, "failed to derive %s by name", path.name)

		byNumber, err := signer.DerivePubKey(ctx, wallet.DerivePubKeyParams{
			Account: wallet.NewAccountSelectorByNumber(
				signerScope, *account.AccountNumber,
			),
			Branch: path.branch,
			Index:  path.index,
		})
		require.NoError(h, err, "failed to derive %s by number", path.name)

		// Assert: Both selectors name the one account, and the locked wallet
		// returned the child that account's XPub defines.
		require.True(
			h, want.IsEqual(byName),
			"%s by name is not the account's child", path.name,
		)
		require.True(
			h, want.IsEqual(byNumber),
			"%s by number is not the account's child", path.name,
		)
	}

	// Act: Derive the account's first external child once more, this time to
	// compare it against the address the wallet issued from that same path.
	external, err := signer.DerivePubKey(ctx, wallet.DerivePubKeyParams{
		Account: wallet.NewAccountSelectorByName(
			signerScope, waddrmgr.DefaultAccountName,
		),
	})
	require.NoError(h, err, "failed to derive the first external child")

	// The address type owns the pubkey-to-address encoding, so reuse it here
	// instead of restating the witness program layout.
	derivedAddr, err := signerAddrType.AddrFromPubKeyBytes(
		external.SerializeCompressed(), h.NetParams(),
	)
	require.NoError(h, err, "failed to encode the derived address")

	// Assert: Derivation and address creation walk the same path, so the
	// wallet's first address pays to the key derivation just returned.
	require.Equal(
		h, firstAddr.String(), derivedAddr.String(),
		"the first external child does not back the first address",
	)
}
