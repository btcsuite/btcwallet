// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build itest

package itest

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// signerAddrType is the address type the derivation cases operate in. Each
// case resolves its key scope from this value, so the two cannot drift: the
// address type owns that mapping.
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
	scope, err := signerAddrType.KeyScope()
	require.NoError(h, err, "failed to resolve the signer key scope")

	w, _ := h.NewWallet(bwtest.WalletFixture{})
	firstAddr := h.NewWalletAddressOfType(w, signerAddrType)

	account, err := w.GetAccount(ctx, scope, waddrmgr.DefaultAccountName)
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
				scope, waddrmgr.DefaultAccountName,
			),
			Branch: path.branch,
			Index:  path.index,
		})
		require.NoError(h, err, "failed to derive %s by name", path.name)

		byNumber, err := signer.DerivePubKey(ctx, wallet.DerivePubKeyParams{
			Account: wallet.NewAccountSelectorByNumber(
				scope, *account.AccountNumber,
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
			scope, waddrmgr.DefaultAccountName,
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

// testSignerDerivePubKeyWalletState verifies that unlocking a started wallet
// does not change the public key derived from an account's extended public key.
func testSignerDerivePubKeyWalletState(h *bwtest.HarnessTest) {
	// Arrange: NewWallet publishes a started, locked wallet, so compare public
	// derivation across lock states through the supported Manager lifecycle.
	ctx := h.Context()
	scope, err := signerAddrType.KeyScope()
	require.NoError(h, err, "failed to resolve the signer key scope")

	w, _ := h.NewWallet(bwtest.WalletFixture{})

	params := wallet.DerivePubKeyParams{
		Account: wallet.NewAccountSelectorByName(
			scope, waddrmgr.DefaultAccountName,
		),
		Branch: 0,
		Index:  5,
	}

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
	scope, err := signerAddrType.KeyScope()
	require.NoError(h, err, "failed to resolve the signer key scope")

	w, _ := h.NewWallet(bwtest.WalletFixture{})
	h.NewWalletAddressOfType(w, signerAddrType)

	defaultAccount := wallet.NewAccountSelectorByName(
		scope, waddrmgr.DefaultAccountName,
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
				scope, "signer absent account",
			),
		},
		expectedErr: wallet.ErrAccountNotInStore,
	}, {
		// A missing number is the same not-found, never account zero.
		name: "unknown account number",
		params: wallet.DerivePubKeyParams{
			Account: wallet.NewAccountSelectorByNumber(
				scope, absentAccountNumber,
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
	scope, err := signerAddrType.KeyScope()
	require.NoError(h, err, "failed to resolve the signer key scope")

	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	h.NewWalletAddressOfType(w, signerAddrType)

	peerKey, err := btcec.NewPrivateKey()
	require.NoError(h, err, "failed to generate the peer key")

	path := wallet.BIP32Path{
		KeyScope: scope,
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
			scope, wallet.AccountNumber(
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

// testSignerECDHWalletState verifies that a started wallet requires unlocking
// for ECDH and returns no secret material when the request is refused.
func testSignerECDHWalletState(h *bwtest.HarnessTest) {
	// Arrange: Use the started, locked fixture and a peer key to check the
	// lock gate through the supported Manager lifecycle.
	ctx := h.Context()
	scope, err := signerAddrType.KeyScope()
	require.NoError(h, err, "failed to resolve the signer key scope")

	w, _ := h.NewWallet(bwtest.WalletFixture{})

	peerKey, err := btcec.NewPrivateKey()
	require.NoError(h, err, "failed to generate the peer key")

	path := wallet.BIP32Path{KeyScope: scope}

	// The account must exist before the path can resolve. Deriving an address
	// materializes it and restores the wallet's locked state.
	h.NewWalletAddressOfType(w, signerAddrType)

	info, err := w.Info(ctx)
	require.NoError(h, err, "failed to query wallet info")
	require.True(h, info.Locked, "wallet is not locked")

	// Act: Exchange while the wallet is locked.
	secret, err := w.ECDH(ctx, path, peerKey.PubKey())

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
	scope, err := signerAddrType.KeyScope()
	require.NoError(h, err, "failed to resolve the signer key scope")

	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	h.NewWalletAddressOfType(w, signerAddrType)

	peerKey, err := btcec.NewPrivateKey()
	require.NoError(h, err, "failed to generate the peer key")

	// Act: Exchange over an account number the wallet does not hold.
	secret, err := w.ECDH(ctx, wallet.BIP32Path{
		KeyScope: scope,
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

// testSignerECDHWatchOnly verifies that a wallet holding only public account
// material serves the public half of an exchange and refuses the secret half,
// so the two Signer operations do not share an availability boundary.
func testSignerECDHWatchOnly(h *bwtest.HarnessTest) {
	const accountName = "signer ecdh watchonly account"

	// Arrange: A started watch-only shell wallet whose one account was seeded
	// from an extended public key. The wallet is left in the state every
	// backend can reach: kvdb has no private material to unlock at all.
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

	peerKey, err := btcec.NewPrivateKey()
	require.NoError(h, err, "failed to generate the peer key")

	// Act: Ask the same wallet for the public half of the exchange.
	_, err = w.DerivePubKey(ctx, wallet.DerivePubKeyParams{
		Account: wallet.NewAccountSelectorByName(keys.scope, accountName),
	})

	// Assert: The public half is available, so the account itself is
	// reachable and the refusal below is not a lookup failure.
	require.NoError(h, err, "watch-only wallet refused public derivation")

	// Act: Ask for the secret half over the same account.
	secret, err := w.ECDH(ctx, wallet.BIP32Path{
		KeyScope: keys.scope,
	}, peerKey.PubKey())

	// Assert: The exchange is refused and hands back nothing, while the public
	// half above stays available. The identity here is the lock gate, not a
	// signing-material check: a watch-only wallet has no private material to
	// unlock, and kvdb refuses to unlock one at all, so this is the furthest
	// state every backend can reach. That is the point of the pairing rather
	// than a weaker assertion: one wallet, public derivation served and the
	// shared secret refused.
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"ECDH on a watch-only wallet not rejected",
	)
	require.Equal(
		h, [32]byte{}, secret, "a refused ECDH returned secret material",
	)
}

// testSignerDerivationDurableReopen verifies that public derivation and the
// shared secret follow the wallet's durable identity rather than the process
// that happened to be holding it open.
func testSignerDerivationDurableReopen(h *bwtest.HarnessTest) {
	// Arrange: A started, unlocked wallet and a peer that outlives the reopen.
	ctx := h.Context()
	scope, err := signerAddrType.KeyScope()
	require.NoError(h, err, "failed to resolve the signer key scope")

	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	h.NewWalletAddressOfType(w, signerAddrType)

	peerKey, err := btcec.NewPrivateKey()
	require.NoError(h, err, "failed to generate the peer key")

	path := wallet.BIP32Path{
		KeyScope: scope,
		DerivationPath: waddrmgr.DerivationPath{
			InternalAccount: 0,
			Branch:          0,
			Index:           9,
		},
	}
	params := wallet.DerivePubKeyParams{
		Account: wallet.NewAccountSelectorByName(
			scope, waddrmgr.DefaultAccountName,
		),
		Branch: path.DerivationPath.Branch,
		Index:  path.DerivationPath.Index,
	}

	// Act: Take both answers from the original wallet.
	before, err := w.DerivePubKey(ctx, params)
	require.NoError(h, err, "failed to derive before the reopen")

	beforeSecret, err := w.ECDH(ctx, path, peerKey.PubKey())
	require.NoError(h, err, "failed to compute the secret before the reopen")
	require.NotEqual(
		h, [32]byte{}, beforeSecret, "the shared secret is the zero value",
	)

	// Stop the wallet, close its Manager, and load the same store again.
	w = h.ReloadWallet(w)

	info, err := w.Info(ctx)
	require.NoError(h, err, "failed to query wallet info")
	require.True(h, info.Locked, "the reopened wallet is not locked")

	// Act: Derive from the reopened wallet while it is still locked.
	after, err := w.DerivePubKey(ctx, params)

	// Assert: The durable identity, not the live wallet, defines the key.
	require.NoError(h, err, "failed to derive after the reopen")
	require.True(
		h, before.IsEqual(after),
		"the reopened wallet derived a different public key",
	)

	h.UnlockWallet(w)

	// Act: Repeat the exchange with the same peer.
	afterSecret, err := w.ECDH(ctx, path, peerKey.PubKey())

	// Assert: The signing key survived the reopen with the public key.
	require.NoError(h, err, "failed to compute the secret after the reopen")
	require.Equal(
		h, beforeSecret, afterSecret,
		"the reopened wallet computed a different shared secret",
	)
}

// testSignerDeriveImportedXPub verifies that an account seeded from an
// extended public key carries no BIP44 number, is reachable for public
// derivation by name alone, and keeps that identity across a reopen.
func testSignerDeriveImportedXPub(h *bwtest.HarnessTest) {
	const (
		accountName = "signer imported xpub"
		branch      = 0
		index       = 7
	)

	// Arrange: A started, locked wallet whose only account was imported from
	// an extended public key the case also holds. A spendable wallet cannot
	// hold such an account on the SQL backends, so the import arrives through
	// the wallet's initial accounts.
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
	require.NoError(h, err, "failed to read the imported account")
	require.True(h, account.IsImported, "the account is not imported")
	require.Nil(
		h, account.AccountNumber,
		"the imported account exposes a BIP44 number",
	)

	branchKey, err := keys.accountKey.Derive(branch)
	require.NoError(h, err, "failed to derive the expected branch")

	childKey, err := branchKey.Derive(index)
	require.NoError(h, err, "failed to derive the expected index")

	want, err := childKey.ECPubKey()
	require.NoError(h, err, "failed to convert the expected child")

	// Act: Select the account by the only identity it has.
	byName, err := w.DerivePubKey(ctx, wallet.DerivePubKeyParams{
		Account: wallet.NewAccountSelectorByName(keys.scope, accountName),
		Branch:  branch,
		Index:   index,
	})

	// Assert: A locked wallet derives the imported XPub's own child.
	require.NoError(h, err, "failed to derive the imported child")
	require.True(
		h, want.IsEqual(byName),
		"the name selector did not reach the imported account",
	)

	// Act: Select the same account by the BIP44 number zero a derived account
	// would hold.
	_, err = w.DerivePubKey(ctx, wallet.DerivePubKeyParams{
		Account: wallet.NewAccountSelectorByNumber(keys.scope, 0),
		Branch:  branch,
		Index:   index,
	})

	// Assert: The account has no portable number, so numeric selection reaches
	// nothing rather than exposing the backend's own account identity.
	require.ErrorIs(
		h, err, wallet.ErrAccountNotInStore,
		"a numbered selector reached the imported account",
	)

	// Act: Derive the same child from the reopened, locked wallet.
	w = h.ReloadWallet(w)
	durable, err := w.DerivePubKey(ctx, wallet.DerivePubKeyParams{
		Account: wallet.NewAccountSelectorByName(keys.scope, accountName),
		Branch:  branch,
		Index:   index,
	})

	// Assert: The name is the account's durable identity, not a handle that
	// only the process holding the wallet open could resolve.
	require.NoError(h, err, "failed to derive after the reopen")
	require.True(
		h, want.IsEqual(durable),
		"the reopened wallet derived a different imported child",
	)
}

// testUnsafeSignerDerivePrivKey checks that extraction matches public
// derivation for the same created account path.
func testUnsafeSignerDerivePrivKey(h *bwtest.HarnessTest) {
	// Arrange: Create one named account through the harness fixture, then
	// derive an independent public oracle for the same account.
	const accountName = "unsafe signer account"

	scope, err := signerAddrType.KeyScope()
	require.NoError(h, err, "failed to resolve the signer key scope")

	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	account := h.CreateTestAccount(w, scope, accountName)

	params := wallet.DerivePubKeyParams{
		Account: wallet.NewAccountSelectorByName(
			scope, accountName,
		),
		Index: 7,
	}
	want, err := w.DerivePubKey(h.Context(), params)
	require.NoError(h, err)

	path := wallet.BIP32Path{
		KeyScope: scope,
		DerivationPath: waddrmgr.DerivationPath{
			InternalAccount: uint32(*account.AccountNumber),
			Branch:          params.Branch,
			Index:           params.Index,
		},
	}

	// Act: Extract the private key for the same account path as the public
	// oracle so the two results can be compared independently.
	key, err := w.DerivePrivKey(h.Context(), path)

	// Assert: NotNil reports only nilness on failure, so it guards the public
	// comparison without including private material in diagnostics.
	require.NoError(h, err)
	require.NotNil(h, key, "expected an extracted key")
	require.Equal(
		h, want.SerializeCompressed(), key.PubKey().SerializeCompressed(),
	)
}

// testUnsafeSignerGetPrivKeyForAddress checks an owned address's extracted key
// against independent public address metadata.
func testUnsafeSignerGetPrivKeyForAddress(h *bwtest.HarnessTest) {
	// Arrange: Use an owned signer address whose public metadata provides an
	// oracle without calling any private-key extraction method.
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	addr := h.NewWalletAddressOfType(w, signerAddrType)
	info, err := w.GetAddressInfo(h.Context(), addr)
	require.NoError(h, err)

	// Act: Resolve the owned address through the wallet to compare the
	// extracted key with the independent public address metadata.
	key, err := w.GetPrivKeyForAddress(h.Context(), addr)

	// Assert: NotNil reports only nilness on failure, so it guards the public
	// comparison without including private material in diagnostics.
	require.NoError(h, err)
	require.NotNil(h, key, "expected an extracted key")
	require.Equal(
		h, info.PubKey.SerializeCompressed(),
		key.PubKey().SerializeCompressed(),
	)
}

// testUnsafeSignerRejectUnknownPath checks the stable absence error for an
// uncreated account in an otherwise materialized scope.
func testUnsafeSignerRejectUnknownPath(h *bwtest.HarnessTest) {
	// Arrange: Create one account, then request its absent successor while
	// unlocked so the result exercises absence rather than the signing gate.
	const accountName = "unsafe signer account"

	scope, err := signerAddrType.KeyScope()
	require.NoError(h, err, "failed to resolve the signer key scope")

	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	account := h.CreateTestAccount(w, scope, accountName)

	path := wallet.BIP32Path{
		KeyScope: scope,
		DerivationPath: waddrmgr.DerivationPath{
			InternalAccount: uint32(*account.AccountNumber) + 1,
		},
	}

	// Act: Request a child of the missing account while a valid account
	// exists in the same scope.
	key, err := w.DerivePrivKey(h.Context(), path)

	// Assert: Every backend must report the public account-absence identity
	// and return no key, rather than falling back to the existing account.
	// Boolean nil checks keep unexpected private values out of diagnostics.
	require.ErrorIs(h, err, wallet.ErrAccountNotInStore)

	keyIsNil := key == nil
	require.True(h, keyIsNil, "expected no private key")
}

// testUnsafeSignerRejectForeignAddress checks that an address not owned by
// the wallet cannot export a key and reports the public extraction error.
func testUnsafeSignerRejectForeignAddress(h *bwtest.HarnessTest) {
	// Arrange: A fresh unlocked wallet does not own the curve generator's
	// public point. Encoding it through the canonical signer address type
	// needs no second wallet or private material.
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	addr, err := signerAddrType.AddrFromPubKeyBytes(
		btcec.Generator().SerializeCompressed(), h.NetParams(),
	)
	require.NoError(h, err, "failed to encode the foreign address")

	// Act: Query the foreign address through the same extraction entry point
	// used for owned addresses.
	key, err := w.GetPrivKeyForAddress(h.Context(), addr)

	// Assert: Absence uses the extraction contract's sentinel on every
	// backend and must never be accompanied by an exported key.
	// Boolean nil checks keep unexpected private values out of diagnostics.
	require.ErrorIs(h, err, wallet.ErrNoAssocPrivateKey)

	keyIsNil := key == nil
	require.True(h, keyIsNil, "expected no private key")
}

// testUnsafeSignerRejectLocked checks both extraction entry points reject a
// locked wallet even when their account and address inputs are valid.
func testUnsafeSignerRejectLocked(h *bwtest.HarnessTest) {
	// Arrange: The address fixture restores the zero-value fixture's locked
	// state after ensuring the default account, leaving valid owned inputs.
	scope, err := signerAddrType.KeyScope()
	require.NoError(h, err, "failed to resolve the signer key scope")

	w, _ := h.NewWallet(bwtest.WalletFixture{})
	addr := h.NewWalletAddressOfType(w, signerAddrType)
	path := wallet.BIP32Path{KeyScope: scope}

	// Act: Exercise both extraction entry points with valid owned inputs
	// while the wallet remains locked.
	pathKey, pathErr := w.DerivePrivKey(h.Context(), path)
	addrKey, addrErr := w.GetPrivKeyForAddress(h.Context(), addr)

	// Assert: Locking forbids both forms of extraction with the same stable
	// state error, and neither method may deliver a key alongside that error.
	// Boolean nil checks keep unexpected private values out of diagnostics.
	require.ErrorIs(h, pathErr, wallet.ErrStateForbidden)

	pathKeyIsNil := pathKey == nil
	require.True(h, pathKeyIsNil, "expected no path key")
	require.ErrorIs(h, addrErr, wallet.ErrStateForbidden)

	addrKeyIsNil := addrKey == nil
	require.True(h, addrKeyIsNil, "expected no address key")
}

// testUnsafeSignerRejectWatchOnly checks that a rootless watch-only wallet
// refuses both extraction methods at the existing signing-state boundary.
func testUnsafeSignerRejectWatchOnly(h *bwtest.HarnessTest) {
	// Arrange: The harness's watch-only shell has no private root. Its signing
	// gate precedes lookup, so public inputs need no imported-key fixture.
	scope, err := signerAddrType.KeyScope()
	require.NoError(h, err, "failed to resolve the signer key scope")

	w, _ := h.NewWallet(bwtest.WalletFixture{WatchOnly: true})
	require.True(h, w.IsWatchOnly(), "fixture must be watch-only")

	path := wallet.BIP32Path{KeyScope: scope}
	addr, err := signerAddrType.AddrFromPubKeyBytes(
		btcec.Generator().SerializeCompressed(), h.NetParams(),
	)
	require.NoError(h, err, "failed to encode the foreign address")

	// Act: Request both forms of extraction from the watch-only wallet to
	// verify that neither entry point bypasses the signing-state gate.
	pathKey, pathErr := w.DerivePrivKey(h.Context(), path)
	addrKey, addrErr := w.GetPrivKeyForAddress(h.Context(), addr)

	// Assert: The maintained Wallet refuses both requests with its existing
	// state sentinel and exports no key, independently of the storage backend.
	// Boolean nil checks keep unexpected private values out of diagnostics.
	require.ErrorIs(h, pathErr, wallet.ErrStateForbidden)

	pathKeyIsNil := pathKey == nil
	require.True(h, pathKeyIsNil, "expected no path key")
	require.ErrorIs(h, addrErr, wallet.ErrStateForbidden)

	addrKeyIsNil := addrKey == nil
	require.True(h, addrKeyIsNil, "expected no address key")
}

// createSignerPath builds a signing selector from public address metadata,
// retaining the account number and child rather than assuming address index 0.
func createSignerPath(derivation *wallet.AddressDerivation) wallet.BIP32Path {
	// Follow wallet.BIP32Path: use the public account number for lookup
	// and harden only the BIP32 account child.
	account := hdkeychain.HardenedKeyStart + derivation.Account

	return wallet.BIP32Path{
		KeyScope: derivation.KeyScope,
		DerivationPath: waddrmgr.DerivationPath{
			InternalAccount:      derivation.Account,
			Account:              account,
			Branch:               derivation.Branch,
			Index:                derivation.Index,
			MasterKeyFingerprint: derivation.MasterKeyFingerprint,
		},
	}
}

// testSignerSignDigestECDSA verifies a persistent Wallet signs for its public
// child key, and that the signature authenticates the requested digest only.
func testSignerSignDigestECDSA(h *bwtest.HarnessTest) {
	// Arrange: The harness materializes the account on every backend. Only
	// public address metadata is retained as the independent signing oracle.
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	addr := h.NewWalletAddressOfType(w, waddrmgr.WitnessPubKey)
	info, err := w.GetAddressInfo(h.Context(), addr)
	require.NoError(h, err)

	digest := chainhash.HashB([]byte("signer digest"))
	intent := &wallet.SignDigestIntent{
		Digest:  digest,
		SigType: wallet.SigTypeECDSA,
	}

	// Act: Sign the fixed digest through the public Wallet entry point.
	result, err := w.SignDigest(
		h.Context(), createSignerPath(info.Derivation), intent,
	)

	// Assert: Check the public result type and verify against the address's
	// public key. A changed digest must fail the same verifier.
	require.NoError(h, err)

	sig, ok := result.(wallet.ECDSASignature)
	require.True(h, ok, "expected ECDSA signature")
	require.True(h, sig.Verify(digest, info.PubKey))
	digest[0] ^= 1
	require.False(h, sig.Verify(digest, info.PubKey))
}

// testSignerSignDigestCompact verifies recoverable ECDSA preserves the
// expected compressed public key without exporting Wallet private material.
func testSignerSignDigestCompact(h *bwtest.HarnessTest) {
	// Arrange: Resolve the public child before requesting the compact format,
	// so recovery is checked against a key independent of the returned bytes.
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	addr := h.NewWalletAddressOfType(w, waddrmgr.WitnessPubKey)
	info, err := w.GetAddressInfo(h.Context(), addr)
	require.NoError(h, err)

	digest := chainhash.HashB([]byte("signer compact digest"))
	intent := &wallet.SignDigestIntent{
		Digest:     digest,
		SigType:    wallet.SigTypeECDSA,
		CompactSig: true,
	}

	// Act: Request a compact signature for the same public address path.
	result, err := w.SignDigest(
		h.Context(), createSignerPath(info.Derivation), intent,
	)

	// Assert: Recovery verifies the signature and exposes the key and
	// compression marker encoded by the public compact-signature contract.
	require.NoError(h, err)

	sig, ok := result.(wallet.CompactSignature)
	require.True(h, ok, "expected compact signature")

	pubKey, compressed, err := ecdsa.RecoverCompact(sig, digest)
	require.NoError(h, err)
	require.True(h, compressed)
	require.True(h, pubKey.IsEqual(info.PubKey))
}

// testSignerSignDigestSchnorr verifies untweaked, BIP86, and script-root
// signatures against independently calculated public output keys.
func testSignerSignDigestSchnorr(h *bwtest.HarnessTest) {
	// Arrange: Nil means no tweak, while an empty non-nil slice requests the
	// BIP86 tweak. Public point arithmetic supplies the expected key for each.
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	addr := h.NewWalletAddressOfType(w, waddrmgr.WitnessPubKey)
	info, err := w.GetAddressInfo(h.Context(), addr)
	require.NoError(h, err)

	digest := chainhash.HashB([]byte("signer schnorr digest"))
	root := chainhash.HashB([]byte("signer script root"))
	tests := []struct {
		name   string
		tweak  []byte
		pubKey *btcec.PublicKey
	}{
		{
			name:   "untweaked",
			pubKey: info.PubKey,
		},
		{
			name:   "bip86",
			tweak:  []byte{},
			pubKey: txscript.ComputeTaprootOutputKey(info.PubKey, nil),
		},
		{
			name:   "script root",
			tweak:  root,
			pubKey: txscript.ComputeTaprootOutputKey(info.PubKey, root),
		},
	}

	// Each row keeps the same signing and verification contract; only the
	// requested tweak and its expected public key change.
	for _, tc := range tests {
		h.Run(tc.name, func(t *testing.T) {
			// Arrange: Bind this row's tweak to the fixed digest and path.
			intent := &wallet.SignDigestIntent{
				Digest:       digest,
				SigType:      wallet.SigTypeSchnorr,
				TaprootTweak: tc.tweak,
			}

			// Act: Let the real Wallet resolve and sign with its key.
			result, err := w.SignDigest(
				t.Context(), createSignerPath(info.Derivation), intent,
			)

			// Assert: Verify the Schnorr result against the public output
			// key, without obtaining or independently signing with a secret.
			require.NoError(t, err)

			sig, ok := result.(wallet.SchnorrSignature)
			require.True(t, ok, "expected Schnorr signature")
			require.True(t, sig.Verify(digest, tc.pubKey))
		})
	}
}

// testSignerRejectDigestIntent verifies public validation identities on a
// signing-capable Wallet, so lock-state rejection cannot mask invalid input.
func testSignerRejectDigestIntent(h *bwtest.HarnessTest) {
	// Arrange: A real, unlocked key path is valid for every row. Digest sizes
	// straddle the supported 32-byte boundary covered by successful cases.
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	addr := h.NewWalletAddressOfType(w, waddrmgr.WitnessPubKey)
	info, err := w.GetAddressInfo(h.Context(), addr)
	require.NoError(h, err)

	digest := chainhash.HashB([]byte("signer rejected digest"))
	tests := []struct {
		name   string
		intent *wallet.SignDigestIntent
		want   error
	}{
		{
			name: "nil intent",
			want: wallet.ErrNilArguments,
		},
		{
			name: "short digest",
			intent: &wallet.SignDigestIntent{
				Digest: digest[:31],
			},
			want: wallet.ErrInvalidDigestSize,
		},
		{
			name: "long digest",
			intent: &wallet.SignDigestIntent{
				Digest: append(digest, 0),
			},
			want: wallet.ErrInvalidDigestSize,
		},
		{
			name: "ecdsa taproot tweak",
			intent: &wallet.SignDigestIntent{
				Digest:       digest,
				TaprootTweak: []byte{},
			},
			want: wallet.ErrInvalidSignParam,
		},
		{
			name: "compact schnorr",
			intent: &wallet.SignDigestIntent{
				Digest:     digest,
				SigType:    wallet.SigTypeSchnorr,
				CompactSig: true,
			},
			want: wallet.ErrInvalidSignParam,
		},
	}

	// Validation rows share the same Wallet and independent request values;
	// no row mutates the wallet or depends on another rejection.
	for _, tc := range tests {
		h.Run(tc.name, func(t *testing.T) {
			// Arrange: Keep the known public derivation valid for this row.
			path := createSignerPath(info.Derivation)

			// Act: Submit the invalid intent through the public method.
			result, err := w.SignDigest(t.Context(), path, tc.intent)

			// Assert: Callers can match the same stable error on every
			// backend, and a rejected request returns no signature.
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, result)
		})
	}
}

// createSignerTx builds a deterministic unsigned spend without chain state.
// Signing needs the previous output's script and amount, not a mined coin.
func createSignerTx(pkScript []byte) (*wire.TxOut, *wire.MsgTx) {
	// One input and one output make SINGLE meaningful, while the lower output
	// value leaves a fee without involving coin selection or publication.
	prevOut := wire.NewTxOut(100000, pkScript)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 0}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(90000, []byte{txscript.OP_TRUE}))

	return prevOut, tx
}

// testSignerComputeUnlockingScript verifies the public result spends each
// supported single-key output under representative signature hash modes.
func testSignerComputeUnlockingScript(h *bwtest.HarnessTest) {
	// Arrange: The harness owns one unlocked Wallet. Every row derives its
	// own address, so its script commits to the key selected by that Wallet.
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	tests := []struct {
		name          string
		addrType      waddrmgr.AddressType
		hashType      txscript.SigHashType
		wantWitness   bool
		wantSigScript bool
	}{
		{
			name:          "legacy all",
			addrType:      waddrmgr.PubKeyHash,
			hashType:      txscript.SigHashAll,
			wantSigScript: true,
		},
		{
			name:        "witness none",
			addrType:    waddrmgr.WitnessPubKey,
			hashType:    txscript.SigHashNone,
			wantWitness: true,
		},
		{
			name:     "nested single anyonecanpay",
			addrType: waddrmgr.NestedWitnessPubKey,
			hashType: txscript.SigHashSingle |
				txscript.SigHashAnyOneCanPay,
			wantWitness:   true,
			wantSigScript: true,
		},
		{
			name:        "taproot default",
			addrType:    waddrmgr.TaprootPubKey,
			hashType:    txscript.SigHashDefault,
			wantWitness: true,
		},
		{
			name:        "taproot all",
			addrType:    waddrmgr.TaprootPubKey,
			hashType:    txscript.SigHashAll,
			wantWitness: true,
		},
	}

	// The same caller assembly and engine verification apply to all rows;
	// only their address, sighash, and expected stack placement differ.
	for _, tc := range tests {
		// Keep harness assertions on the parent test's goroutine; the
		// child uses the resulting address only as public fixture data.
		addr := h.NewWalletAddressOfType(w, tc.addrType)

		h.Run(tc.name, func(t *testing.T) {
			// Arrange: Build a fresh transaction and its hash cache from
			// the exact previous output, without asking the Wallet to sign.
			pkScript, err := txscript.PayToAddrScript(addr)
			require.NoError(t, err)

			prevOut, tx := createSignerTx(pkScript)
			fetcher := txscript.NewCannedPrevOutputFetcher(
				prevOut.PkScript, prevOut.Value,
			)
			hashes := txscript.NewTxSigHashes(tx, fetcher)
			params := &wallet.UnlockingScriptParams{
				Tx:        tx,
				Output:    prevOut,
				SigHashes: hashes,
				HashType:  tc.hashType,
			}

			// Act: Request the complete unlocking data for this output.
			unlocking, err := w.ComputeUnlockingScript(t.Context(), params)

			// Assert: Apply the returned stacks unchanged. The script
			// engine verifies their signature against the previous output.
			require.NoError(t, err)
			require.Equal(t, tc.wantWitness, len(unlocking.Witness) != 0)
			require.Equal(t, tc.wantSigScript, len(unlocking.SigScript) != 0)
			tx.TxIn[0].Witness = unlocking.Witness
			tx.TxIn[0].SignatureScript = unlocking.SigScript

			engine, err := txscript.NewEngine(
				pkScript, tx, 0, txscript.StandardVerifyFlags,
				nil, hashes, prevOut.Value, fetcher,
			)
			require.NoError(t, err)
			require.NoError(t, engine.Execute())
		})
	}
}

// testSignerRejectUnlockingScript verifies absent parameters, addressless
// scripts, and foreign outputs cannot produce unlocking material.
func testSignerRejectUnlockingScript(h *bwtest.HarnessTest) {
	// Arrange: An unlocked Wallet reaches parameter and output validation.
	// The generator's public encoding supplies a foreign address without
	// constructing or obtaining any private key.
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	pubKey, err := hex.DecodeString(
		"0279be667ef9dcbbac55a06295ce870b070" +
			"29bfcdb2dce28d959f2815b16f81798",
	)
	require.NoError(h, err)

	addr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey), h.NetParams(),
	)
	require.NoError(h, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err)

	prevOut, tx := createSignerTx(pkScript)
	fetcher := txscript.NewCannedPrevOutputFetcher(pkScript, prevOut.Value)
	hashes := txscript.NewTxSigHashes(tx, fetcher)
	tests := []struct {
		name   string
		params *wallet.UnlockingScriptParams
		want   error
	}{
		{
			name: "nil params",
			want: wallet.ErrNilArguments,
		},
		{
			name: "missing output",
			params: &wallet.UnlockingScriptParams{
				Tx:        tx,
				SigHashes: hashes,
				HashType:  txscript.SigHashAll,
			},
			want: wallet.ErrNilArguments,
		},
		{
			name: "addressless script",
			params: &wallet.UnlockingScriptParams{
				Tx: tx,
				Output: wire.NewTxOut(
					prevOut.Value, []byte{txscript.OP_RETURN},
				),
				SigHashes: hashes,
				HashType:  txscript.SigHashAll,
			},
			want: wallet.ErrUnableToExtractAddress,
		},
		{
			name: "foreign output",
			params: &wallet.UnlockingScriptParams{
				Tx:        tx,
				Output:    prevOut,
				SigHashes: hashes,
				HashType:  txscript.SigHashAll,
			},
			want: wallet.ErrAddressNotFound,
		},
	}

	// These requests share a valid spend shape and differ only at the
	// documented rejection boundary; none changes Wallet state.
	for _, tc := range tests {
		h.Run(tc.name, func(t *testing.T) {
			// Arrange: Use the row's request without repairing its invalid
			// field, so the caller-visible validation remains the subject.
			params := tc.params

			// Act: Try to assemble unlocking data through the public API.
			unlocking, err := w.ComputeUnlockingScript(t.Context(), params)

			// Assert: Every database must return the same public identity
			// and no partial witness or scriptSig on rejection.
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, unlocking)
		})
	}
}

// testSignerComputeRawSigLegacy verifies a caller can use the returned legacy
// signature, including its sighash byte, to assemble a valid P2PKH scriptSig.
func testSignerComputeRawSigLegacy(h *bwtest.HarnessTest) {
	// Arrange: Derive an owned legacy address and retain its public key and
	// path. The transaction fixture supplies a fixed previous output amount.
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	addr := h.NewWalletAddressOfType(w, waddrmgr.PubKeyHash)
	info, err := w.GetAddressInfo(h.Context(), addr)
	require.NoError(h, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err)

	prevOut, tx := createSignerTx(pkScript)
	fetcher := txscript.NewCannedPrevOutputFetcher(pkScript, prevOut.Value)
	hashes := txscript.NewTxSigHashes(tx, fetcher)
	params := &wallet.RawSigParams{
		Tx:        tx,
		Output:    prevOut,
		SigHashes: hashes,
		HashType:  txscript.SigHashAll,
		Path:      createSignerPath(info.Derivation),
		Details:   wallet.LegacySpendDetails{},
	}

	// Act: Request the raw signature without asking the Wallet to assemble it.
	rawSig, err := w.ComputeRawSig(h.Context(), params)

	// Assert: Push the returned bytes and expected public key unchanged. A
	// missing or incorrect sighash byte makes script execution fail.
	require.NoError(h, err)

	sigScript, err := txscript.NewScriptBuilder().
		AddData(rawSig).AddData(info.PubKey.SerializeCompressed()).Script()
	require.NoError(h, err)

	tx.TxIn[0].SignatureScript = sigScript

	engine, err := txscript.NewEngine(
		pkScript, tx, 0, txscript.StandardVerifyFlags,
		nil, hashes, prevOut.Value, fetcher,
	)
	require.NoError(h, err)
	require.NoError(h, engine.Execute())
}

// testSignerComputeRawSigSegwit verifies raw Segwit v0 signatures omit the
// sighash byte and authenticate the previous output using the P2PKH scriptCode.
func testSignerComputeRawSigSegwit(h *bwtest.HarnessTest) {
	// Arrange: Construct the scriptCode from the expected public key, rather
	// than obtaining it or a completed witness from another Wallet signer.
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	addr := h.NewWalletAddressOfType(w, waddrmgr.WitnessPubKey)
	info, err := w.GetAddressInfo(h.Context(), addr)
	require.NoError(h, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err)

	keyAddr, err := address.NewAddressPubKeyHash(
		address.Hash160(info.PubKey.SerializeCompressed()), h.NetParams(),
	)
	require.NoError(h, err)

	scriptCode, err := txscript.PayToAddrScript(keyAddr)
	require.NoError(h, err)

	prevOut, tx := createSignerTx(pkScript)
	fetcher := txscript.NewCannedPrevOutputFetcher(pkScript, prevOut.Value)
	hashes := txscript.NewTxSigHashes(tx, fetcher)
	params := &wallet.RawSigParams{
		Tx:        tx,
		Output:    prevOut,
		SigHashes: hashes,
		HashType:  txscript.SigHashAll,
		Path:      createSignerPath(info.Derivation),
		Details: wallet.SegwitV0SpendDetails{
			WitnessScript: scriptCode,
		},
	}

	// Act: Sign through the public raw-signature entry point.
	rawSig, err := w.ComputeRawSig(h.Context(), params)

	// Assert: Append the caller's sighash byte before constructing the
	// witness. The engine proves the signature fits the public key and amount.
	require.NoError(h, err)

	tx.TxIn[0].Witness = wire.TxWitness{
		append(rawSig, byte(params.HashType)),
		info.PubKey.SerializeCompressed(),
	}

	engine, err := txscript.NewEngine(
		pkScript, tx, 0, txscript.StandardVerifyFlags,
		nil, hashes, prevOut.Value, fetcher,
	)
	require.NoError(h, err)
	require.NoError(h, engine.Execute())
}

// testSignerComputeRawSigTaproot verifies key-path signatures commit to the
// requested script root and preserve default versus explicit sighash encoding.
func testSignerComputeRawSigTaproot(h *bwtest.HarnessTest) {
	// Arrange: Public point arithmetic builds an output with a script-root
	// tweak. Raw signing takes a key path, so this output need not be imported.
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	addr := h.NewWalletAddressOfType(w, waddrmgr.TaprootPubKey)
	info, err := w.GetAddressInfo(h.Context(), addr)
	require.NoError(h, err)

	root := chainhash.HashB([]byte("signer raw taproot root"))
	outputKey := txscript.ComputeTaprootOutputKey(info.PubKey, root)
	outputAddr, err := address.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey), h.NetParams(),
	)
	require.NoError(h, err)

	pkScript, err := txscript.PayToAddrScript(outputAddr)
	require.NoError(h, err)

	tests := []struct {
		name     string
		hashType txscript.SigHashType
		size     int
	}{
		{
			name:     "default",
			hashType: txscript.SigHashDefault,
			size:     schnorr.SignatureSize,
		},
		{
			name:     "all",
			hashType: txscript.SigHashAll,
			size:     schnorr.SignatureSize + 1,
		},
	}

	// Each encoding must produce a valid spend of the same tweaked output.
	for _, tc := range tests {
		h.Run(tc.name, func(t *testing.T) {
			// Arrange: Each row gets an unsigned input and a fresh cache,
			// so a previous witness cannot affect the requested signature.
			prevOut, tx := createSignerTx(pkScript)
			fetcher := txscript.NewCannedPrevOutputFetcher(
				pkScript, prevOut.Value,
			)
			hashes := txscript.NewTxSigHashes(tx, fetcher)
			params := &wallet.RawSigParams{
				Tx:        tx,
				Output:    prevOut,
				SigHashes: hashes,
				HashType:  tc.hashType,
				Path:      createSignerPath(info.Derivation),
				Details: wallet.TaprootSpendDetails{
					SpendPath: wallet.KeyPathSpend,
					Tweak:     root,
				},
			}

			// Act: Sign for the caller-constructed Taproot output.
			rawSig, err := w.ComputeRawSig(t.Context(), params)

			// Assert: Use the returned encoding without adding a sighash
			// byte; the engine checks the tweak and hash mode together.
			require.NoError(t, err)
			require.Len(t, rawSig, tc.size)
			tx.TxIn[0].Witness = wire.TxWitness{rawSig}

			engine, err := txscript.NewEngine(
				pkScript, tx, 0, txscript.StandardVerifyFlags,
				nil, hashes, prevOut.Value, fetcher,
			)
			require.NoError(t, err)
			require.NoError(t, engine.Execute())
		})
	}
}

// testSignerComputeRawSigTapscript verifies a caller can spend a CHECKSIG leaf
// with the raw signature and a publicly constructed script-tree proof.
func testSignerComputeRawSigTapscript(h *bwtest.HarnessTest) {
	// Arrange: The public key defines both the CHECKSIG leaf and internal
	// key. Only txscript's public tree operations construct the control block.
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	addr := h.NewWalletAddressOfType(w, waddrmgr.TaprootPubKey)
	info, err := w.GetAddressInfo(h.Context(), addr)
	require.NoError(h, err)

	script, err := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(info.PubKey)).
		AddOp(txscript.OP_CHECKSIG).Script()
	require.NoError(h, err)

	tree := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(script))
	root := tree.RootNode.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(info.PubKey, root[:])
	outputAddr, err := address.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey), h.NetParams(),
	)
	require.NoError(h, err)

	pkScript, err := txscript.PayToAddrScript(outputAddr)
	require.NoError(h, err)

	control := tree.LeafMerkleProofs[0].ToControlBlock(info.PubKey)
	controlBytes, err := control.ToBytes()
	require.NoError(h, err)

	prevOut, tx := createSignerTx(pkScript)
	fetcher := txscript.NewCannedPrevOutputFetcher(pkScript, prevOut.Value)
	hashes := txscript.NewTxSigHashes(tx, fetcher)
	params := &wallet.RawSigParams{
		Tx:        tx,
		Output:    prevOut,
		SigHashes: hashes,
		HashType:  txscript.SigHashDefault,
		Path:      createSignerPath(info.Derivation),
		Details: wallet.TaprootSpendDetails{
			SpendPath:     wallet.ScriptPathSpend,
			WitnessScript: script,
		},
	}

	// Act: Request a raw signature for the caller's script-path intent.
	rawSig, err := w.ComputeRawSig(h.Context(), params)

	// Assert: Script execution checks the signature, leaf commitment, and
	// control block independently of the Wallet's signing implementation.
	require.NoError(h, err)

	tx.TxIn[0].Witness = wire.TxWitness{rawSig, script, controlBytes}

	engine, err := txscript.NewEngine(
		pkScript, tx, 0, txscript.StandardVerifyFlags,
		nil, hashes, prevOut.Value, fetcher,
	)
	require.NoError(h, err)
	require.NoError(h, engine.Execute())
}

// testSignerRejectRawSig verifies absent requests/details and unknown Taproot
// spend paths return stable public errors without raw signing material.
func testSignerRejectRawSig(h *bwtest.HarnessTest) {
	// Arrange: A real unlocked Taproot path ensures version-specific rejection
	// is reached without depending on a missing account or unavailable key.
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	addr := h.NewWalletAddressOfType(w, waddrmgr.TaprootPubKey)
	info, err := w.GetAddressInfo(h.Context(), addr)
	require.NoError(h, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err)

	prevOut, tx := createSignerTx(pkScript)
	fetcher := txscript.NewCannedPrevOutputFetcher(pkScript, prevOut.Value)
	hashes := txscript.NewTxSigHashes(tx, fetcher)
	tests := []struct {
		name   string
		params *wallet.RawSigParams
		want   error
	}{
		{
			name: "nil params",
			want: wallet.ErrNilArguments,
		},
		{
			name: "missing details",
			params: &wallet.RawSigParams{
				Tx:        tx,
				Output:    prevOut,
				SigHashes: hashes,
				Path:      createSignerPath(info.Derivation),
			},
			want: wallet.ErrNilArguments,
		},
		{
			name: "unknown spend path",
			params: &wallet.RawSigParams{
				Tx:        tx,
				Output:    prevOut,
				SigHashes: hashes,
				Path:      createSignerPath(info.Derivation),
				Details: wallet.TaprootSpendDetails{
					SpendPath: wallet.ScriptPathSpend + 1,
				},
			},
			want: wallet.ErrUnknownSignMethod,
		},
	}

	// Arrange is complete for every independent rejection row. No backend
	// branch or alternative successful result weakens their public contract.
	for _, tc := range tests {
		h.Run(tc.name, func(t *testing.T) {
			// Act: Submit the row's unsupported request through the Wallet.
			rawSig, err := w.ComputeRawSig(t.Context(), tc.params)

			// Assert: Preserve error identity and return no usable bytes.
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, rawSig)
		})
	}
}
