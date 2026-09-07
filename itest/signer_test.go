// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build itest

package itest

import (
	"github.com/btcsuite/btcd/btcec/v2"
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

// testSignerDerivePubKeyWalletState verifies that public derivation is gated
// on a running wallet alone, and that unlocking does not change its answer.
func testSignerDerivePubKeyWalletState(h *bwtest.HarnessTest) {
	// Arrange: A wallet that has been created but not started.
	ctx := h.Context()
	w, _ := h.NewWallet(bwtest.WalletFixture{Unstarted: true})

	params := wallet.DerivePubKeyParams{
		Account: wallet.NewAccountSelectorByName(
			signerScope, waddrmgr.DefaultAccountName,
		),
		Branch: 0,
		Index:  5,
	}

	// Act: Derive before the wallet runs.
	_, err := w.DerivePubKey(ctx, params)

	// Assert: The request is refused by the state gate.
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"derivation before start not rejected",
	)

	require.NoError(h, w.Start(ctx), "failed to start wallet")

	// The account must exist before it can be selected. Deriving an address
	// materializes it and restores the wallet's locked state.
	h.NewWalletAddressOfType(w, signerAddrType)

	info, err := w.Info(ctx)
	require.NoError(h, err, "failed to query wallet info")
	require.True(h, info.Locked, "wallet is not locked")

	// Act: Derive while the wallet is locked. The account extended public key
	// is stored in the clear, so no private material is needed.
	locked, err := w.DerivePubKey(ctx, params)

	// Assert: A started wallet serves the request whether or not it is locked.
	require.NoError(h, err, "locked wallet refused public derivation")

	h.UnlockWallet(w)

	// Act: Derive the same child from the now unlocked wallet.
	unlocked, err := w.DerivePubKey(ctx, params)

	// Assert: Unlocking grants no additional public derivation, so the two
	// answers are the same key.
	require.NoError(h, err, "unlocked wallet refused public derivation")
	require.True(
		h, locked.IsEqual(unlocked),
		"unlocking changed the derived public key",
	)
}

// testSignerDerivePubKeyRejectRequest verifies that a malformed selector, an
// account the wallet does not hold, and a hardened path are each refused with
// a stable error identity rather than resolving to some other account or
// child.
func testSignerDerivePubKeyRejectRequest(h *bwtest.HarnessTest) {
	// absentAccountNumber is a BIP44 account number no test wallet creates.
	const absentAccountNumber = 4242

	// Arrange: A started wallet holding only its default account.
	ctx := h.Context()
	w, _ := h.NewWallet(bwtest.WalletFixture{})
	h.NewWalletAddressOfType(w, signerAddrType)

	defaultAccount := wallet.NewAccountSelectorByName(
		signerScope, waddrmgr.DefaultAccountName,
	)

	testCases := []struct {
		name        string
		params      wallet.DerivePubKeyParams
		expectedErr error
	}{{
		// A selector must name exactly one account identity, and the
		// zero value names none.
		name:        "selector names no account",
		params:      wallet.DerivePubKeyParams{},
		expectedErr: wallet.ErrInvalidAccountSelector,
	}, {
		// A missing name is a not-found, never a fallback to the
		// default account.
		name: "unknown account name",
		params: wallet.DerivePubKeyParams{
			Account: wallet.NewAccountSelectorByName(
				signerScope, "signer absent account",
			),
		},
		expectedErr: wallet.ErrAccountNotInStore,
	}, {
		// A missing number is the same not-found, never account zero.
		name: "unknown account number",
		params: wallet.DerivePubKeyParams{
			Account: wallet.NewAccountSelectorByNumber(
				signerScope, absentAccountNumber,
			),
		},
		expectedErr: wallet.ErrAccountNotInStore,
	}, {
		// An account is scoped, so the name the wallet does hold must
		// not resolve under a scope it has no manager for.
		name: "unknown key scope",
		params: wallet.DerivePubKeyParams{
			Account: wallet.NewAccountSelectorByName(
				waddrmgr.KeyScope{Purpose: 9999, Coin: 9999},
				waddrmgr.DefaultAccountName,
			),
		},
		expectedErr: wallet.ErrAccountNotInStore,
	}, {
		// The first hardened branch, one above the largest branch
		// testSignerDerivePubKeyPaths derives successfully.
		name: "hardened branch",
		params: wallet.DerivePubKeyParams{
			Account: defaultAccount,
			Branch:  hdkeychain.HardenedKeyStart,
		},
		expectedErr: hdkeychain.ErrDeriveHardFromPublic,
	}, {
		// The index is bounded the same way the branch is.
		name: "hardened index",
		params: wallet.DerivePubKeyParams{
			Account: defaultAccount,
			Index:   hdkeychain.HardenedKeyStart,
		},
		expectedErr: hdkeychain.ErrDeriveHardFromPublic,
	}}

	for _, testCase := range testCases {
		// Act: Send the rejected request.
		_, err := w.DerivePubKey(ctx, testCase.params)

		// Assert: The wallet refuses it by a stable identity.
		require.ErrorIs(
			h, err, testCase.expectedErr, "%s not rejected",
			testCase.name,
		)
	}
}

// testSignerDerivePubKeyWatchOnly verifies that a wallet holding only public
// account material still serves public derivation, and returns the children
// the imported extended public key defines.
func testSignerDerivePubKeyWatchOnly(h *bwtest.HarnessTest) {
	const (
		accountName = "signer watchonly account"
		branch      = 1
		index       = 4
	)

	// Arrange: A watch-only shell wallet seeded with one account whose
	// extended public key the case also holds, so the expected child can be
	// derived without the wallet.
	ctx := h.Context()
	keys := deterministicImportedAccountKeys(h)
	w, _ := h.NewWallet(bwtest.WalletFixture{
		InitialAccounts: []wallet.WatchOnlyAccount{{
			Scope:                keys.scope,
			XPub:                 keys.accountKey,
			MasterKeyFingerprint: keys.masterKeyFingerprint,
			Name:                 accountName,
			AddrType:             keys.addrType,
		}},
	})

	account, err := w.GetAccount(ctx, keys.scope, accountName)
	require.NoError(h, err, "failed to read the watch-only account")
	require.True(h, account.IsWatchOnly, "account is not watch-only")

	branchKey, err := keys.accountKey.Derive(branch)
	require.NoError(h, err, "failed to derive the expected branch")

	childKey, err := branchKey.Derive(index)
	require.NoError(h, err, "failed to derive the expected index")

	want, err := childKey.ECPubKey()
	require.NoError(h, err, "failed to convert the expected child")

	// Act: Derive the child through the public Signer request.
	got, err := w.DerivePubKey(ctx, wallet.DerivePubKeyParams{
		Account: wallet.NewAccountSelectorByName(keys.scope, accountName),
		Branch:  branch,
		Index:   index,
	})

	// Assert: A wallet with no private material at all resolves the account
	// and returns that account's child.
	require.NoError(h, err, "watch-only wallet refused public derivation")
	require.True(
		h, want.IsEqual(got),
		"watch-only derivation is not the account's child",
	)
}

// testSignerECDHAgreement verifies that the shared secret the wallet computes
// is the one an independent peer computes from the wallet's public key, and
// that it is bound to both the peer key and the derivation path.
func testSignerECDHAgreement(h *bwtest.HarnessTest) {
	// Arrange: A started, unlocked wallet and a peer key generated here, so
	// the peer half of the exchange is never known to the wallet.
	ctx := h.Context()
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	h.NewWalletAddressOfType(w, signerAddrType)

	peerKey, err := btcec.NewPrivateKey()
	require.NoError(h, err, "failed to generate the peer key")

	path := wallet.BIP32Path{
		KeyScope: signerScope,
		DerivationPath: waddrmgr.DerivationPath{
			InternalAccount: 0,
			Branch:          0,
			Index:           3,
		},
	}

	// The wallet's half of the exchange is public. Take it from the public
	// derivation request, which also proves the numbered selector and the
	// BIP32 path name the same account.
	walletPub, err := w.DerivePubKey(ctx, wallet.DerivePubKeyParams{
		Account: wallet.NewAccountSelectorByNumber(
			signerScope, wallet.AccountNumber(
				path.DerivationPath.InternalAccount,
			),
		),
		Branch: path.DerivationPath.Branch,
		Index:  path.DerivationPath.Index,
	})
	require.NoError(h, err, "failed to derive the wallet's public key")

	var want [32]byte
	copy(want[:], btcec.GenerateSharedSecret(peerKey, walletPub))

	// Act: Compute the same secret from the wallet's side.
	secret, err := w.ECDH(ctx, path, peerKey.PubKey())

	// Assert: Both sides of the exchange reach the same secret, and it is not
	// the degenerate value they would share if neither had computed anything.
	require.NoError(h, err, "failed to compute the shared secret")
	require.Equal(
		h, want, secret, "wallet and peer disagree on the shared secret",
	)
	require.NotEqual(
		h, [32]byte{}, secret, "the shared secret is the zero value",
	)

	otherPeerKey, err := btcec.NewPrivateKey()
	require.NoError(h, err, "failed to generate the second peer key")

	// Act: Exchange with a different peer over the same wallet key.
	otherPeerSecret, err := w.ECDH(ctx, path, otherPeerKey.PubKey())

	// Assert: The secret is bound to the peer key.
	require.NoError(h, err, "failed to compute the second peer's secret")
	require.NotEqual(
		h, secret, otherPeerSecret,
		"a different peer key produced the same secret",
	)

	internalPath := path
	internalPath.DerivationPath.Branch = 1

	// Act: Exchange with the original peer over the account's internal branch.
	internalSecret, err := w.ECDH(ctx, internalPath, peerKey.PubKey())

	// Assert: The secret is bound to the derivation path as well, so the
	// wallet is not answering from one fixed key.
	require.NoError(h, err, "failed to compute the internal branch secret")
	require.NotEqual(
		h, secret, internalSecret,
		"a different branch produced the same secret",
	)
}

// testSignerECDHWalletState verifies that the shared secret is gated on a
// running and unlocked wallet, and that a refused request returns no secret
// material.
func testSignerECDHWalletState(h *bwtest.HarnessTest) {
	// Arrange: A wallet that has been created but not started, and a peer to
	// exchange with.
	ctx := h.Context()
	w, _ := h.NewWallet(bwtest.WalletFixture{Unstarted: true})

	peerKey, err := btcec.NewPrivateKey()
	require.NoError(h, err, "failed to generate the peer key")

	path := wallet.BIP32Path{KeyScope: signerScope}

	// Act: Exchange before the wallet runs.
	secret, err := w.ECDH(ctx, path, peerKey.PubKey())

	// Assert: The state gate refuses, and hands back nothing.
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"ECDH before start not rejected",
	)
	require.Equal(
		h, [32]byte{}, secret, "a refused ECDH returned secret material",
	)

	require.NoError(h, w.Start(ctx), "failed to start wallet")

	// The account must exist before the path can resolve. Deriving an address
	// materializes it and restores the wallet's locked state.
	h.NewWalletAddressOfType(w, signerAddrType)

	info, err := w.Info(ctx)
	require.NoError(h, err, "failed to query wallet info")
	require.True(h, info.Locked, "wallet is not locked")

	// Act: Exchange while the wallet is locked.
	secret, err = w.ECDH(ctx, path, peerKey.PubKey())

	// Assert: Unlike public derivation, the shared secret needs the private
	// key, so a locked wallet refuses before reaching the store.
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"ECDH while locked not rejected",
	)
	require.Equal(
		h, [32]byte{}, secret, "a refused ECDH returned secret material",
	)

	h.UnlockWallet(w)

	// Act: Exchange once the wallet can sign.
	secret, err = w.ECDH(ctx, path, peerKey.PubKey())

	// Assert: Unlocking is the whole difference.
	require.NoError(h, err, "unlocked wallet refused ECDH")
	require.NotEqual(
		h, [32]byte{}, secret, "unlocked ECDH returned no secret",
	)
}

// testSignerECDHRejectAccount verifies that an unlocked wallet still refuses
// an exchange it holds no signing key for, without returning secret material
// or falling back to another account.
func testSignerECDHRejectAccount(h *bwtest.HarnessTest) {
	// absentAccountNumber is a BIP44 account number no test wallet creates.
	const absentAccountNumber = 4242

	// Arrange: A started, unlocked wallet holding only its default account.
	ctx := h.Context()
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	h.NewWalletAddressOfType(w, signerAddrType)

	peerKey, err := btcec.NewPrivateKey()
	require.NoError(h, err, "failed to generate the peer key")

	// Act: Exchange over an account number the wallet does not hold.
	secret, err := w.ECDH(ctx, wallet.BIP32Path{
		KeyScope: signerScope,
		DerivationPath: waddrmgr.DerivationPath{
			InternalAccount: absentAccountNumber,
		},
	}, peerKey.PubKey())

	// Assert: The missing account is reported, never replaced by account zero.
	require.ErrorIs(
		h, err, wallet.ErrAccountNotInStore,
		"ECDH over an unknown account not rejected",
	)
	require.Equal(
		h, [32]byte{}, secret, "a refused ECDH returned secret material",
	)

	// Act: Exchange over a key scope the wallet has no manager for.
	secret, err = w.ECDH(ctx, wallet.BIP32Path{
		KeyScope: waddrmgr.KeyScope{Purpose: 9999, Coin: 9999},
	}, peerKey.PubKey())

	// Assert: The path is scoped, so an unknown scope cannot reach the
	// account the wallet does hold.
	require.ErrorIs(
		h, err, wallet.ErrAccountNotInStore,
		"ECDH under an unknown key scope not rejected",
	)
	require.Equal(
		h, [32]byte{}, secret, "a refused ECDH returned secret material",
	)
}
