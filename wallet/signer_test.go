// Copyright (c) 2020 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest/keyvaultmock"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	sqlitedb "github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	// errManagerNotFound is returned when a scoped manager cannot be found.
	errManagerNotFound = errors.New("manager not found")

	// errDerivationFailed is returned when a key derivation fails.
	errDerivationFailed = errors.New("derivation failed")

	// errPrivKeyMock is a mock error for private key retrieval.
	errPrivKeyMock = errors.New("privkey error")

	// errTweakMock is a mock error for private key tweaking.
	errTweakMock = errors.New("tweak error")

	// errSignMock is a mock error for signing operations.
	errSignMock = errors.New("sign error")
)

// expectStorePubKey wires the store-routed public-key lookup for a derived
// address: the account xpub is public metadata, so it comes from the account
// read rather than the secret read, and the leaf key is derived from it
// locally.
// It returns the leaf public key the wallet will derive at the path's branch
// and
// index.
func expectStorePubKey(t *testing.T, mocks *mockWalletDeps,
	walletID uint32, scope waddrmgr.KeyScope,
	path waddrmgr.DerivationPath) *btcec.PublicKey {

	t.Helper()

	acct := testAccountXPrv(t)
	acctPub, err := acct.Neuter()
	require.NoError(t, err)

	mocks.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID:      walletID,
		Scope:         db.KeyScope(scope),
		AccountNumber: &path.InternalAccount,
		SkipBalance:   true,
	}).Return(&db.AccountInfo{
		PublicKey: []byte(acctPub.String()),
	}, nil).Once()

	_, pubKey := deriveLeafKeys(t, acct, path.Branch, path.Index)

	return pubKey
}

// TestDerivePubKeySuccess tests the successful derivation of a public key
// through the store account extended public key.
func TestDerivePubKeySuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet with mocks and a derivation path, and wire
	// the store account-secret lookup that the pubkey resolver reads.
	w, mocks := createUnlockedWalletWithMocks(t)

	scope := waddrmgr.KeyScopeBIP0084
	path := waddrmgr.DerivationPath{
		InternalAccount: 0,
		Branch:          0,
		Index:           0,
	}
	params := DerivePubKeyParams{
		Account: NewAccountSelectorByNumber(scope, 0),
		Branch:  path.Branch,
		Index:   path.Index,
	}

	pubKey := expectStorePubKey(t, mocks, w.id, scope, path)

	// Act: Derive the public key.
	derivedKey, err := w.DerivePubKey(t.Context(), params)

	// Assert: Check that the correct key is returned without error.
	require.NoError(t, err)
	require.True(t, pubKey.IsEqual(derivedKey))
}

// TestPublicKeyDerivationByName verifies that semantic name selection reads
// the selected account XPub and derives its requested child.
func TestPublicKeyDerivationByName(t *testing.T) {
	t.Parallel()

	// Arrange: Store a distinct account XPub behind a name-only selector so
	// the test proves semantic lookup, rather than numeric fallback, owns the
	// derived child.
	w, mocks := createUnlockedWalletWithMocks(t)
	accountName := "imported-xpub"
	account := testAccountXPrv(t)
	accountPub, err := account.Neuter()
	require.NoError(t, err)
	_, want := deriveLeafKeys(t, account, 1, 7)

	mocks.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID:    w.id,
		Scope:       db.KeyScope(waddrmgr.KeyScopeBIP0084),
		Name:        &accountName,
		SkipBalance: true,
	}).Return(&db.AccountInfo{
		PublicKey: []byte(accountPub.String()),
	}, nil).Once()

	// Act: Derive the requested child through the public semantic API.
	got, err := w.DerivePubKey(
		t.Context(), DerivePubKeyParams{
			Account: NewAccountSelectorByName(
				waddrmgr.KeyScopeBIP0084, accountName,
			),
			Branch: 1,
			Index:  7,
		},
	)

	// Assert: The name-selected XPub produced the expected leaf key.
	require.NoError(t, err)
	require.True(t, want.IsEqual(got))
}

// TestPublicKeyDerivationRejectsInvalidSelector verifies selector validation
// fails before the durable Store is accessed.
func TestPublicKeyDerivationRejectsInvalidSelector(t *testing.T) {
	t.Parallel()

	// Arrange: Keep the selector empty and retain the Store mock so the test
	// can prove validation rejects it before any backend lookup.
	w, mocks := createUnlockedWalletWithMocks(t)

	// Act: Attempt public derivation without an account identity.
	_, err := w.DerivePubKey(
		t.Context(), DerivePubKeyParams{},
	)

	// Assert: Selector validation failed locally and the Store was untouched.
	require.ErrorIs(t, err, errInvalidAccountSelector)
	mocks.store.AssertNotCalled(t, "GetAccount", mock.Anything, mock.Anything)
}

// TestDerivePubKeyDeriveFails verifies that a failure inside public-child
// derivation itself propagates. The other retained Store tests cover account
// absence, an unexpected Store error, and missing account public material, but
// none reaches deriveStoredAccountChildPubKey's branch/index error path: a
// hardened child cannot be derived from a public key, so the account xpub here
// is valid and only the requested child is unreachable.
func TestDerivePubKeyDeriveFails(t *testing.T) {
	t.Parallel()

	// Arrange: a valid account xpub in the Store, and a derivation path
	// whose branch is hardened.
	w, mocks := createUnlockedWalletWithMocks(t)

	scope := waddrmgr.KeyScopeBIP0084
	accountNumber := uint32(0)
	params := DerivePubKeyParams{
		Account: NewAccountSelectorByNumber(scope, 0),
		Branch:  hdkeychain.HardenedKeyStart,
		Index:   0,
	}

	acct := testAccountXPrv(t)
	acctPub, err := acct.Neuter()
	require.NoError(t, err)

	mocks.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID:      w.id,
		Scope:         db.KeyScope(scope),
		AccountNumber: &accountNumber,
		SkipBalance:   true,
	}).Return(&db.AccountInfo{
		PublicKey: []byte(acctPub.String()),
	}, nil).Once()

	// Act: Attempt to derive the public key.
	_, err = w.DerivePubKey(t.Context(), params)

	// Assert: the derivation error is propagated, not masked as a missing
	// account or a Store failure.
	require.ErrorIs(t, err, hdkeychain.ErrDeriveHardFromPublic)
	mocks.store.AssertExpectations(t)
}

// TestDerivePubKeyAccountNotInStore tests the failure case where the owning
// account is not present in the store.
func TestDerivePubKeyAccountNotInStore(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and a test path. Configure the store to
	// report that the account row is absent.
	w, mocks := createUnlockedWalletWithMocks(t)
	accountNumber := uint32(0)
	params := DerivePubKeyParams{
		Account: NewAccountSelectorByNumber(
			waddrmgr.KeyScopeBIP0084, 0,
		),
	}

	mocks.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID:      w.id,
		Scope:         db.KeyScope(waddrmgr.KeyScopeBIP0084),
		AccountNumber: &accountNumber,
		SkipBalance:   true,
	}).Return((*db.AccountInfo)(nil), db.ErrAccountNotFound).Once()

	// Act: Attempt to derive the public key.
	_, err := w.DerivePubKey(t.Context(), params)

	// Assert: Check that the account-miss error is surfaced.
	require.ErrorIs(t, err, ErrAccountNotInStore)
	mocks.store.AssertExpectations(t)
}

// TestDerivePubKeyStoreFails tests that an unexpected store error is
// propagated rather than masked.
func TestDerivePubKeyStoreFails(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and a test path. Configure the store to
	// return an unexpected error.
	w, mocks := createUnlockedWalletWithMocks(t)
	accountNumber := uint32(0)
	params := DerivePubKeyParams{
		Account: NewAccountSelectorByNumber(
			waddrmgr.KeyScopeBIP0084, 0,
		),
	}

	mocks.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID:      w.id,
		Scope:         db.KeyScope(waddrmgr.KeyScopeBIP0084),
		AccountNumber: &accountNumber,
		SkipBalance:   true,
	}).Return((*db.AccountInfo)(nil), errDerivationFailed).Once()

	// Act: Attempt to derive the public key.
	_, err := w.DerivePubKey(t.Context(), params)

	// Assert: Check that the error is propagated correctly.
	require.ErrorIs(t, err, errDerivationFailed)
}

// TestDerivePubKeyMissingAccountPubKey tests the failure case where the store
// account carries no extended public key.
func TestDerivePubKeyMissingAccountPubKey(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and a test path. Configure the store to
	// return an account with an empty public key.
	w, mocks := createUnlockedWalletWithMocks(t)
	accountNumber := uint32(0)
	params := DerivePubKeyParams{
		Account: NewAccountSelectorByNumber(
			waddrmgr.KeyScopeBIP0084, 0,
		),
	}

	mocks.store.On("GetAccount", mock.Anything, db.GetAccountQuery{
		WalletID:      w.id,
		Scope:         db.KeyScope(waddrmgr.KeyScopeBIP0084),
		AccountNumber: &accountNumber,
		SkipBalance:   true,
	}).Return(&db.AccountInfo{}, nil).Once()

	// Act: Attempt to derive the public key.
	_, err := w.DerivePubKey(t.Context(), params)

	// Assert: Check that the missing-material error is surfaced.
	require.ErrorIs(t, err, ErrMissingParam)
}

// TestECDHSuccess tests the successful ECDH key exchange.
func TestECDHSuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and mocks.
	w, mocks := createUnlockedWalletWithMocks(t)

	remoteKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	remotePubKey := remoteKey.PubKey()

	path := BIP32Path{
		KeyScope: waddrmgr.KeyScopeBIP0084,
		DerivationPath: waddrmgr.DerivationPath{
			InternalAccount: 0,
			Branch:          0,
			Index:           0,
		},
	}

	// The ECDH key is resolved through the store account secret; take the
	// leaf private key the signer will derive so we can compute the
	// expected shared secret independently.
	privKey, _ := expectStoreSignerPrivKey(
		t, mocks, w.id, path.KeyScope, path.DerivationPath,
	)

	// Compute the expected shared secret before ECDH runs, since ECDH
	// zeroes the private key it derived internally (a separate copy from
	// this one).
	expectedSecret := btcec.GenerateSharedSecret(privKey, remotePubKey)

	var expectedSecretArray [32]byte
	copy(expectedSecretArray[:], expectedSecret)

	// Act: Perform the ECDH operation.
	sharedSecret, err := w.ECDH(t.Context(), path, remotePubKey)

	// Assert: Check that the correct shared secret is returned.
	require.NoError(t, err)
	require.Equal(t, expectedSecretArray, sharedSecret)
}

// TestECDHFails tests the failure case where the key derivation fails during
// an ECDH operation.
func TestECDHFails(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and configure the store account-secret
	// lookup to fail with an unexpected error.
	w, mocks := createUnlockedWalletWithMocks(t)
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}

	remoteKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	remotePubKey := remoteKey.PubKey()

	accountNumber := path.DerivationPath.InternalAccount
	mocks.store.On("GetAccountSecret", mock.Anything,
		db.GetAccountSecretQuery{
			WalletID:      w.id,
			Scope:         db.KeyScope(path.KeyScope),
			AccountNumber: accountNumber,
		}).Return((*db.AccountSecret)(nil), errDerivationFailed).Once()

	// Act: Attempt to perform the ECDH operation.
	_, err = w.ECDH(t.Context(), path, remotePubKey)

	// Assert: Check that the error is propagated correctly.
	require.ErrorIs(t, err, errDerivationFailed)
}

// deterministicPrivKey is a helper function that returns a deterministic
// private and public key pair for testing purposes.
func deterministicPrivKey(t *testing.T) (*btcec.PrivateKey, *btcec.PublicKey) {
	t.Helper()

	pkBytes, err := hex.DecodeString("22a47fa09a223f2aa079edf85a7c2d4f87" +
		"20ee63e502ee2869afab7de234b80c")
	require.NoError(t, err)

	privKey, pubKey := btcec.PrivKeyFromBytes(pkBytes)

	return privKey, pubKey
}

// testAccountXPrv is a deterministic account-level extended private key used to
// back the store-routed signer path in mock-based tests. Its child keys are
// derived locally, and the store + vault mocks are programmed to return this
// xprv, so the signer resolves the same leaf key the test derives.
func testAccountXPrv(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()

	seed := bytes.Repeat([]byte{0x2E}, hdkeychain.RecommendedSeedLen)
	master, err := hdkeychain.NewMaster(seed, &chainParams)
	require.NoError(t, err)

	// A non-hardened child stands in for the account key; the exact path is
	// irrelevant because the signer never re-derives above the account.
	acct, err := master.Derive(7)
	require.NoError(t, err)

	return acct
}

// deriveLeafKeys derives the leaf private and public keys at the given branch
// and index from an account extended private key, mirroring the local
// derivation the store-routed signer performs after decrypting the account
// xprv.
func deriveLeafKeys(t *testing.T, acct *hdkeychain.ExtendedKey,
	branch, index uint32) (*btcec.PrivateKey, *btcec.PublicKey) {

	t.Helper()

	branchKey, err := acct.Derive(branch)
	require.NoError(t, err)

	leafKey, err := branchKey.Derive(index)
	require.NoError(t, err)

	privKey, err := leafKey.ECPrivKey()
	require.NoError(t, err)

	pubKey, err := leafKey.ECPubKey()
	require.NoError(t, err)

	return privKey, pubKey
}

// expectStoreSignerPrivKey wires the store-routed signer private-key lookup for
// a derived address: the account secret is fetched by account number and its
// encrypted extended private key is decrypted through the vault. The vault mock
// runs as an identity cipher, so the plaintext handed to the signer is the
// account xprv string itself.
//
// It returns the leaf private and public keys the signer will derive at the
// path's branch and index, so callers can build the matching address and assert
// against the recovered key.
func expectStoreSignerPrivKey(t *testing.T, mocks *mockWalletDeps,
	walletID uint32, scope waddrmgr.KeyScope,
	path waddrmgr.DerivationPath) (*btcec.PrivateKey, *btcec.PublicKey) {

	t.Helper()

	acct := testAccountXPrv(t)
	encAcctPriv := []byte(acct.String())

	accountNumber := path.InternalAccount
	mocks.store.On("GetAccountSecret", mock.Anything,
		db.GetAccountSecretQuery{
			WalletID:      walletID,
			Scope:         db.KeyScope(scope),
			AccountNumber: accountNumber,
		}).Return(&db.AccountSecret{
		EncryptedPrivateKey: encAcctPriv,
	}, nil).Once()

	mocks.vault.On("Decrypt", waddrmgr.CKTPrivate, encAcctPriv).Return(
		identityDecrypt, nil,
	).Once()

	privKey, pubKey := deriveLeafKeys(t, acct, path.Branch, path.Index)

	return privKey, pubKey
}

// identityDecrypt is a vault decrypt stub that returns the ciphertext
// unchanged, standing in for a real decrypt of never-encrypted test material.
func identityDecrypt(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)

	return out
}

// TestSignDigest tests the signing of a message digest with different signature
// types.
func TestSignDigest(t *testing.T) {
	t.Parallel()

	// We'll use a common set of parameters for all signing test cases to
	// ensure the only variable is the signing intent itself. The signing
	// key is resolved through the store account secret, so the concrete
	// key pair is produced per case by expectStoreSignerPrivKey.
	path := BIP32Path{
		KeyScope: waddrmgr.KeyScopeBIP0084,
		DerivationPath: waddrmgr.DerivationPath{
			InternalAccount: 0,
			Branch:          0,
			Index:           0,
		},
	}
	msg := []byte("test message")
	msgHash := chainhash.HashB(msg)
	msgDoubleHash := chainhash.DoubleHashB(msg)
	tag := []byte("test tag")
	taggedHash := chainhash.TaggedHash(tag, msg)

	testCases := []struct {
		// name is the name of the test case.
		name string

		// intent is the signing intent to use for the test.
		intent *SignDigestIntent

		// verify is a function that verifies the signature produced by
		// the signing intent against the resolved leaf key pair.
		verify func(t *testing.T, sig Signature,
			privKey *btcec.PrivateKey, pubKey *btcec.PublicKey)
	}{
		{
			name: "ECDSA success",
			intent: &SignDigestIntent{
				Digest:     msgHash,
				SigType:    SigTypeECDSA,
				CompactSig: false,
			},
			verify: func(t *testing.T, sig Signature,
				_ *btcec.PrivateKey, pubKey *btcec.PublicKey) {

				t.Helper()

				ecdsaSig, ok := sig.(ECDSASignature)
				require.True(t, ok, "expected ECDSASignature")
				require.True(
					t, ecdsaSig.Verify(msgHash, pubKey),
					"signature invalid",
				)
			},
		},
		{
			name: "ECDSA compact success",
			intent: &SignDigestIntent{
				Digest:     msgDoubleHash,
				SigType:    SigTypeECDSA,
				CompactSig: true,
			},
			verify: func(t *testing.T, sig Signature,
				_ *btcec.PrivateKey, pubKey *btcec.PublicKey) {

				t.Helper()

				compactSig, ok := sig.(CompactSignature)
				require.True(t, ok, "expected CompactSignature")
				recoveredKey, _, err := ecdsa.RecoverCompact(
					compactSig, msgDoubleHash,
				)
				require.NoError(t, err)
				require.True(
					t, recoveredKey.IsEqual(pubKey),
					"recovered key mismatch",
				)
			},
		},
		{
			name: "Schnorr success",
			intent: &SignDigestIntent{
				Digest:  taggedHash[:],
				SigType: SigTypeSchnorr,
			},
			verify: func(t *testing.T, sig Signature,
				_ *btcec.PrivateKey, pubKey *btcec.PublicKey) {

				t.Helper()

				schnorrSig, ok := sig.(SchnorrSignature)
				require.True(t, ok, "expected SchnorrSignature")

				require.True(t,
					schnorrSig.Verify(
						taggedHash[:], pubKey,
					),
					"signature invalid",
				)
			},
		},
		{
			name: "Schnorr success with tweak",
			intent: &SignDigestIntent{
				Digest:       msgHash,
				SigType:      SigTypeSchnorr,
				TaprootTweak: []byte("test tweak"),
			},
			verify: func(t *testing.T, sig Signature,
				privKey *btcec.PrivateKey, _ *btcec.PublicKey) {

				t.Helper()

				schnorrSig, ok := sig.(SchnorrSignature)
				require.True(t, ok, "expected SchnorrSignature")

				// Calculate expected tweaked key and hash
				tweak := []byte("test tweak")
				tweakedKey := txscript.TweakTaprootPrivKey(
					*privKey, tweak,
				)
				tweakedPub := tweakedKey.PubKey()

				require.True(t,
					schnorrSig.Verify(msgHash, tweakedPub),
					"signature invalid for tweaked key",
				)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Set up a mock wallet whose store account
			// secret resolves to a deterministic account xprv, so
			// the signer derives a known leaf key for the path.
			w, mocks := createUnlockedWalletWithMocks(t)

			privKey, pubKey := expectStoreSignerPrivKey(
				t, mocks, w.id, path.KeyScope,
				path.DerivationPath,
			)

			// Act: Attempt to sign the message with the wallet.
			sig, err := w.SignDigest(t.Context(), path, tc.intent)

			// Assert: Verify that the signature was created
			// successfully and is valid for the resolved leaf key.
			require.NoError(t, err)
			tc.verify(t, sig, privKey, pubKey)
		})
	}
}

// TestSignDigestFail tests failure modes of SignDigest through the store-routed
// key path.
func TestSignDigestFail(t *testing.T) {
	t.Parallel()

	w, mocks := createUnlockedWalletWithMocks(t)
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}

	accountNumber := path.DerivationPath.InternalAccount
	query := db.GetAccountSecretQuery{
		WalletID:      w.id,
		Scope:         db.KeyScope(path.KeyScope),
		AccountNumber: accountNumber,
	}

	digest := make([]byte, 32)
	intent := &SignDigestIntent{Digest: digest}

	// Test Case 1: The signing account is not in the store. We expect
	// ErrAccountNotInStore to be returned.
	mocks.store.On("GetAccountSecret", mock.Anything, query).Return(
		(*db.AccountSecret)(nil), db.ErrAccountNotFound,
	).Once()

	_, err := w.SignDigest(t.Context(), path, intent)
	require.ErrorIs(t, err, ErrAccountNotInStore)

	// Test Case 2: The account exists but is watch-only (no encrypted
	// private material). We expect ErrWatchOnlyAccount to be returned.
	mocks.store.On("GetAccountSecret", mock.Anything, query).Return(
		&db.AccountSecret{}, nil,
	).Once()

	_, err = w.SignDigest(t.Context(), path, intent)
	require.ErrorIs(t, err, ErrWatchOnlyAccount)
}

// TestValidateSignDigestIntent tests the validation logic for SignDigestIntent.
func TestValidateSignDigestIntent(t *testing.T) {
	t.Parallel()

	validDigest := make([]byte, 32)
	invalidDigest := make([]byte, 31)

	testCases := []struct {
		name    string
		intent  *SignDigestIntent
		wantErr error
	}{
		{
			// A valid ECDSA intent with a 32-byte digest and no
			// restricted fields should pass validation.
			name: "valid ECDSA",
			intent: &SignDigestIntent{
				Digest:  validDigest,
				SigType: SigTypeECDSA,
			},
			wantErr: nil,
		},
		{
			// A valid Schnorr intent with a 32-byte digest and no
			// restricted fields should pass validation.
			name: "valid Schnorr",
			intent: &SignDigestIntent{
				Digest:  validDigest,
				SigType: SigTypeSchnorr,
			},
			wantErr: nil,
		},
		{
			// If the digest length is not 32 bytes, we expect an
			// ErrInvalidDigestSize error.
			name: "invalid digest length",
			intent: &SignDigestIntent{
				Digest:  invalidDigest,
				SigType: SigTypeECDSA,
			},
			wantErr: ErrInvalidDigestSize,
		},
		{
			// If an ECDSA intent provides a Taproot Tweak, we
			// expect an ErrInvalidSignParam error as tweaks are
			// Schnorr-specific.
			name: "ECDSA with Taproot Tweak",
			intent: &SignDigestIntent{
				Digest:       validDigest,
				SigType:      SigTypeECDSA,
				TaprootTweak: []byte("tweak"),
			},
			wantErr: ErrInvalidSignParam,
		},
		{
			// If a Schnorr intent requests a Compact Signature, we
			// expect an ErrInvalidSignParam error as compact sigs
			// are ECDSA-specific.
			name: "Schnorr with CompactSig",
			intent: &SignDigestIntent{
				Digest:     validDigest,
				SigType:    SigTypeSchnorr,
				CompactSig: true,
			},
			wantErr: ErrInvalidSignParam,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateSignDigestIntent(tc.intent)
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestComputeUnlockingScriptP2PKH tests that the wallet can generate a valid
// unlocking script for a P2PKH output.
func TestComputeUnlockingScriptP2PKH(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and a dummy transaction that will be used
	// to spend the P2PKH output.
	w, mocks := createUnlockedWalletWithMocks(t)

	// The signer resolves the private key through the store account secret,
	// so program that path and take the leaf keys it will derive.
	scope := waddrmgr.KeyScopeBIP0044
	path := waddrmgr.DerivationPath{
		InternalAccount: 0,
		Account:         0,
		Branch:          0,
		Index:           0,
	}
	_, pubKey := expectStoreSignerPrivKey(t, mocks, w.id, scope, path)

	// Create a P2PKH address for the derived leaf public key and the
	// corresponding previous output script.
	addr, err := address.NewAddressPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()),
		w.cfg.ChainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	// The wallet resolves the address metadata through the store; the
	// derivation scope makes the metadata directly usable for signing.
	expectSignerAddressInfoWithKeyScope(
		t, w, mocks, addr, db.PubKeyHash, false, false, pubKey, scope,
	)

	// Act: With the setup complete, we can now ask the wallet to compute
	// the unlocking script.
	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	params := &UnlockingScriptParams{
		Tx:         tx,
		InputIndex: 0,
		Output:     prevOut,
		SigHashes:  sigHashes,
		HashType:   txscript.SigHashAll,
	}
	script, err := w.ComputeUnlockingScript(t.Context(), params)
	require.NoError(t, err)

	// Assert: The computed script should be a valid unlocking script for
	// the P2PKH output. We verify this by creating a new script engine
	// and executing it with the generated script. A successful execution
	// proves the script is correct.
	require.NotNil(t, script.SigScript)
	require.Nil(t, script.Witness)
	tx.TxIn[0].SignatureScript = script.SigScript

	vm, err := txscript.NewEngine(
		prevOut.PkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		sigHashes, prevOut.Value, fetcher,
	)
	require.NoError(t, err)
	require.NoError(t, vm.Execute(), "script execution failed")
}

// TestComputeUnlockingScriptP2WKH tests that the wallet can generate a valid
// unlocking script for a P2WKH output.
func TestComputeUnlockingScriptP2WKH(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and a dummy transaction that will be used
	// to spend the P2WKH output.
	w, mocks := createUnlockedWalletWithMocks(t)

	scope := waddrmgr.KeyScopeBIP0084
	path := waddrmgr.DerivationPath{
		InternalAccount: 0,
		Account:         0,
		Branch:          0,
		Index:           0,
	}
	_, pubKey := expectStoreSignerPrivKey(t, mocks, w.id, scope, path)

	// Create a P2WKH address for the derived leaf public key and the
	// corresponding previous output script.
	addr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()),
		w.cfg.ChainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	// The wallet resolves the address metadata through the store; the
	// derivation scope makes the metadata directly usable for signing.
	expectSignerAddressInfoWithKeyScope(
		t, w, mocks, addr, db.WitnessPubKey, false, false, pubKey,
		scope,
	)

	// Act: With the setup complete, we can now ask the wallet to compute
	// the unlocking script.
	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	params := &UnlockingScriptParams{
		Tx:         tx,
		InputIndex: 0,
		Output:     prevOut,
		SigHashes:  sigHashes,
		HashType:   txscript.SigHashAll,
	}
	script, err := w.ComputeUnlockingScript(t.Context(), params)
	require.NoError(t, err)

	// Assert: The computed script should be a valid unlocking script. For
	// P2WKH, this means a nil SigScript and a non-nil Witness. We verify
	// this by creating a new script engine and executing it.
	require.Nil(t, script.SigScript)
	require.NotNil(t, script.Witness)
	tx.TxIn[0].Witness = script.Witness

	vm, err := txscript.NewEngine(
		prevOut.PkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		sigHashes, prevOut.Value, fetcher,
	)
	require.NoError(t, err)
	require.NoError(t, vm.Execute(), "script execution failed")
}

// TestComputeUnlockingScriptNP2WKH tests that the wallet can generate a valid
// unlocking script for a nested P2WKH output.
func TestComputeUnlockingScriptNP2WKH(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and a dummy transaction.
	w, mocks := createUnlockedWalletWithMocks(t)

	scope := waddrmgr.KeyScopeBIP0049Plus
	path := waddrmgr.DerivationPath{
		InternalAccount: 0,
		Account:         0,
		Branch:          0,
		Index:           0,
	}
	_, pubKey := expectStoreSignerPrivKey(t, mocks, w.id, scope, path)

	// Create a NP2WKH address for the derived leaf public key. This is a
	// P2WKH output nested within a P2SH output. This is done by creating
	// the witness program first, and then using its hash in a P2SH script.
	p2sh, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(address.Hash160(pubKey.SerializeCompressed())).
		Script()
	require.NoError(t, err)
	addr, err := address.NewAddressScriptHash(p2sh, w.cfg.ChainParams)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	// The wallet resolves the address metadata through the store; the
	// derivation scope makes the metadata directly usable for signing. The
	// nested witness program is rebuilt from the address public key.
	expectSignerAddressInfoWithKeyScope(
		t, w, mocks, addr, db.NestedWitnessPubKey, false, false, pubKey,
		scope,
	)

	// Act: With the setup complete, we can now ask the wallet to compute
	// the unlocking script.
	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	params := &UnlockingScriptParams{
		Tx:         tx,
		InputIndex: 0,
		Output:     prevOut,
		SigHashes:  sigHashes,
		HashType:   txscript.SigHashAll,
	}
	script, err := w.ComputeUnlockingScript(t.Context(), params)
	require.NoError(t, err)

	// Assert: The computed script should be a valid unlocking script. For
	// NP2WKH, this means both a non-nil SigScript (containing the redeem
	// script) and a non-nil Witness. We verify this by creating a new
	// script engine and executing it.
	require.NotNil(t, script.SigScript)
	require.NotNil(t, script.Witness)
	tx.TxIn[0].SignatureScript = script.SigScript
	tx.TxIn[0].Witness = script.Witness

	vm, err := txscript.NewEngine(
		prevOut.PkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		sigHashes, prevOut.Value, fetcher,
	)
	require.NoError(t, err)
	require.NoError(t, vm.Execute(), "script execution failed")
}

// TestComputeUnlockingScriptP2TR tests that the wallet can generate a valid
// unlocking script for a P2TR key-path spend.
func TestComputeUnlockingScriptP2TR(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet, keys, and a dummy transaction.
	w, mocks := createUnlockedWalletWithMocks(t)

	scope := waddrmgr.KeyScopeBIP0086
	path := waddrmgr.DerivationPath{
		InternalAccount: 0,
		Account:         0,
		Branch:          0,
		Index:           0,
	}
	_, pubKey := expectStoreSignerPrivKey(t, mocks, w.id, scope, path)

	// Create a P2TR address for a key-path spend of the derived leaf public
	// key. This involves computing the taproot output key from the internal
	// public key.
	addr, err := address.NewAddressTaproot(
		schnorr.SerializePubKey(
			txscript.ComputeTaprootOutputKey(pubKey, nil),
		), w.cfg.ChainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	// The wallet resolves the address metadata through the store; the
	// derivation scope makes the metadata directly usable for signing.
	expectSignerAddressInfoWithKeyScope(
		t, w, mocks, addr, db.TaprootPubKey, false, false, pubKey,
		scope,
	)

	// Act: With the setup complete, we can now ask the wallet to compute
	// the unlocking script. For Taproot, we must use a multi-output
	// fetcher, as the sighash calculation (specifically with
	// SigHashDefault) requires access to all previous outputs being spent
	// in the transaction.
	fetcher := txscript.NewMultiPrevOutFetcher(
		map[wire.OutPoint]*wire.TxOut{{Index: 0}: prevOut},
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	params := &UnlockingScriptParams{
		Tx:         tx,
		InputIndex: 0,
		Output:     prevOut,
		SigHashes:  sigHashes,
		HashType:   txscript.SigHashDefault,
	}
	script, err := w.ComputeUnlockingScript(t.Context(), params)
	require.NoError(t, err)

	// Assert: The computed script should be a valid unlocking script. For a
	// P2TR key-path spend, this means a nil SigScript and a non-nil
	// Witness containing just the Schnorr signature. We verify this by
	// creating a new script engine and executing it.
	require.Nil(t, script.SigScript)
	require.NotNil(t, script.Witness)
	tx.TxIn[0].Witness = script.Witness

	vm, err := txscript.NewEngine(
		prevOut.PkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		sigHashes, prevOut.Value, fetcher,
	)
	require.NoError(t, err)
	require.NoError(t, vm.Execute(), "script execution failed")
}

// TestComputeUnlockingScriptSQLDerivedAddress verifies that an address created
// only in the SQL address store can still be signed for using its derivation
// metadata.
func TestComputeUnlockingScriptSQLDerivedAddress(t *testing.T) {
	t.Parallel()

	w, chain, vault := newSQLAddressSigningWallet(t)
	require.NotNil(t, vault)

	chain.On(
		"NotifyReceived",
		mock.MatchedBy(func(addrs []address.Address) bool {
			return len(addrs) == 1
		}),
	).Return(nil).Once()

	addr, err := w.NewAddress(
		t.Context(), "default", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)
	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	params := &UnlockingScriptParams{
		Tx:         tx,
		InputIndex: 0,
		Output:     prevOut,
		SigHashes:  sigHashes,
		HashType:   txscript.SigHashAll,
	}

	script, err := w.ComputeUnlockingScript(t.Context(), params)
	require.NoError(t, err)
	require.Nil(t, script.SigScript)
	require.NotNil(t, script.Witness)

	tx.TxIn[0].Witness = script.Witness
	vm, err := txscript.NewEngine(
		prevOut.PkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		sigHashes, prevOut.Value, fetcher,
	)
	require.NoError(t, err)
	require.NoError(t, vm.Execute(), "script execution failed")
}

// TestResolveDerivedPrivKeyFromStoreDerivedSuccess exercises the store-backed
// success path end to end: the account's encrypted extended private key is
// fetched from the store, decrypted through the key vault under CKTPrivate, the
// account xprv is parsed, and the leaf key at a specific branch and index is
// derived. It asserts the recovered leaf key equals one derived independently
// from the same account xprv, so a wrong crypto-key selection on decrypt or a
// bad child derivation cannot slip through unnoticed.
//
// Unlike the identity-cipher helpers used elsewhere, the stored ciphertext here
// is deliberately distinct from the plaintext xprv, so the assertion only holds
// if the vault Decrypt call is actually made and its output is what gets
// parsed.
func TestResolveDerivedPrivKeyFromStoreDerivedSuccess(t *testing.T) {
	t.Parallel()

	// Arrange: a real account xprv whose leaf key the signer must recover,
	// and a marked ciphertext that differs from the plaintext so the
	// decrypt step is load-bearing.
	w, mocks := createUnlockedWalletWithMocks(t)

	acct := testAccountXPrv(t)
	plaintextXPrv := []byte(acct.String())
	encAcctPriv := append([]byte("vault-ciphertext:"), plaintextXPrv...)
	require.NotEqual(t, plaintextXPrv, encAcctPriv)

	scope := waddrmgr.KeyScopeBIP0084
	path := waddrmgr.DerivationPath{
		InternalAccount: 4,
		Branch:          1,
		Index:           5,
	}

	// The store returns the encrypted account material keyed by account
	// number (path-only caller, so accountID is nil below).
	accountNumber := path.InternalAccount
	mocks.store.On("GetAccountSecret", mock.Anything,
		db.GetAccountSecretQuery{
			WalletID:      w.id,
			Scope:         db.KeyScope(scope),
			AccountNumber: accountNumber,
		}).Return(&db.AccountSecret{
		EncryptedPrivateKey: encAcctPriv,
	}, nil).Once()

	// The vault decrypts the ciphertext under the private crypto key back
	// to the plaintext account xprv. Returning a closure lets the mock
	// ignore the (distinct) ciphertext input and hand back the known
	// plaintext.
	mocks.vault.On("Decrypt", waddrmgr.CKTPrivate, encAcctPriv).Return(
		func([]byte) []byte {
			out := make([]byte, len(plaintextXPrv))
			copy(out, plaintextXPrv)

			return out
		}, nil,
	).Once()

	// The expected leaf key, derived independently from the same account
	// xprv at the same branch and index.
	wantPriv, _ := deriveLeafKeys(t, acct, path.Branch, path.Index)

	// Act: resolve the derived private key through the store.
	gotPriv, err := w.resolveDerivedPrivKeyFromStore(
		t.Context(), scope, path,
	)

	// Assert: the decrypt -> parse -> derive chain produced the exact leaf
	// key, proving the crypto-key type and child derivation are correct.
	require.NoError(t, err)
	require.Equal(t, wantPriv.Serialize(), gotPriv.Serialize())
	gotPriv.Zero()
}

// TestGetPrivKeyForAddressSQLDerivedAddress verifies that GetPrivKeyForAddress
// recovers the private key for an address owned by a SQL-only account, driving
// the store-secret + vault-decrypt fallback rather than any waddrmgr-mirrored
// material.
//
// The "default" account (number 0) is mirrored between the SQL store and the
// legacy waddrmgr manager (both seeded identically), so signing it does not
// distinguish the store path from a legacy lookup. This test instead signs from
// a secondary account that exists ONLY in the SQL store (a non-zero account
// number), so the recovered key can only come from the store's encrypted
// account secret decrypted through the vault.
func TestGetPrivKeyForAddressSQLDerivedAddress(t *testing.T) {
	t.Parallel()

	w, chain, vault := newSQLAddressSigningWallet(t)

	// Create a second derived account that lives only in the SQL store; it
	// has no counterpart in the legacy waddrmgr manager.
	secondary, err := w.store.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID: w.id,
			Scope:    db.KeyScope(waddrmgr.KeyScopeBIP0084),
			Name:     "secondary",
		}, testAccountDerivationFunc(),
	)
	require.NoError(t, err)
	require.NotNil(t, secondary.AccountNumber)
	require.NotNil(t, secondary.AccountID)

	// The secondary account must not be the wallet's default account 0,
	// which is the one mirrored through waddrmgr.
	require.NotZero(t, *secondary.AccountNumber)

	chain.On(
		"NotifyReceived",
		mock.MatchedBy(func(addrs []address.Address) bool {
			return len(addrs) == 1
		}),
	).Return(nil).Once()

	addr, err := w.NewAddress(
		t.Context(), "secondary", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)

	// Read back the store's view of the address so the expected leaf key is
	// derived at exactly the branch and index the store assigned.
	info, err := w.GetAddressInfo(t.Context(), addr)
	require.NoError(t, err)
	require.NotNil(t, info.Derivation, "SQL-derived address must carry "+
		"derivation metadata")
	require.Equal(
		t, *secondary.AccountNumber, info.Derivation.Account,
	)

	// Independently derive the expected leaf key from the same seed the
	// SQL account derivation used, at the secondary account number and the
	// store-assigned branch and index.
	seed := bytes.Repeat([]byte{0x5A}, hdkeychain.RecommendedSeedLen)
	master, err := hdkeychain.NewMaster(seed, &chainParams)
	require.NoError(t, err)
	acctKey, err := deriveBIP44AccountKey(
		master, db.KeyScope(waddrmgr.KeyScopeBIP0084),
		*secondary.AccountNumber,
	)
	require.NoError(t, err)
	wantPriv, _ := deriveLeafKeys(
		t, acctKey, info.Derivation.Branch, info.Derivation.Index,
	)

	// Act: resolve the private key. This drives GetAccountSecret keyed by
	// the durable account id and decrypts the account xprv through the
	// vault.
	priv, err := w.GetPrivKeyForAddress(t.Context(), addr)
	require.NoError(t, err, "GetPrivKeyForAddress must succeed for "+
		"SQL-only derived addresses")
	require.NotNil(t, priv)

	// Assert: the recovered key matches the independently derived leaf key,
	// and the vault's private decrypt path actually ran.
	require.Equal(t, wantPriv.Serialize(), priv.Serialize())
	vault.AssertCalled(t, "Decrypt", waddrmgr.CKTPrivate, mock.Anything)
	priv.Zero()
}

// TestNewAddressOnSQLOnlyAccount verifies that SQL-owned accounts can derive
// receive addresses without a mirrored legacy waddrmgr account.
//
// The test exercises the public-key path; signer coverage for SQL-only
// accounts is provided by TestGetPrivKeyForAddressSQLDerivedAddress.
func TestNewAddressOnSQLOnlyAccount(t *testing.T) {
	t.Parallel()

	w, chain, _ := newSQLAddressSigningWallet(t)

	_, err := w.store.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID: w.id,
			Scope:    db.KeyScope(waddrmgr.KeyScopeBIP0084),
			Name:     "secondary",
		}, testAccountDerivationFunc(),
	)
	require.NoError(t, err)

	chain.On(
		"NotifyReceived",
		mock.MatchedBy(func(addrs []address.Address) bool {
			return len(addrs) == 1
		}),
	).Return(nil).Once()

	addr, err := w.NewAddress(
		t.Context(), "secondary", waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)
	require.NotNil(t, addr)
}

// TestComputeUnlockingScriptFail_ScriptForOutput tests failure when
// ScriptForOutput returns an error.
func TestComputeUnlockingScriptFail_ScriptForOutput(t *testing.T) {
	t.Parallel()

	// Arrange: Set up keys, address, and transaction.
	_, pubKey := deterministicPrivKey(t)
	addr, err := address.NewAddressPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// Create fresh mutable state.
	prevOut, tx := createDummyTestTx(pkScript)
	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)

	// Arrange: Set up the wallet and mocks.
	w, mocks := createUnlockedWalletWithMocks(t)

	// Mock the store to return an error.
	pkScript_, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)
	mocks.store.On("GetAddress", mock.Anything, db.GetAddressQuery{
		WalletID:     w.id,
		ScriptPubKey: pkScript_,
	}).Return((*db.AddressInfo)(nil), errManagerNotFound).Once()

	params := &UnlockingScriptParams{
		Tx:        tx,
		Output:    prevOut,
		SigHashes: sigHashes,
		HashType:  txscript.SigHashAll,
	}

	// Act: Attempt to compute the unlocking script.
	_, err = w.ComputeUnlockingScript(t.Context(), params)

	// Assert: Verify error.
	require.ErrorContains(t, err, "unable to get address info")
}

// TestComputeUnlockingScriptFail_PrivKey tests failure when the store-routed
// private key resolution fails.
func TestComputeUnlockingScriptFail_PrivKey(t *testing.T) {
	t.Parallel()

	// Arrange: Set up keys, address, and transaction.
	_, pubKey := deterministicPrivKey(t)
	addr, err := address.NewAddressPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// Create fresh mutable state.
	prevOut, tx := createDummyTestTx(pkScript)
	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)

	// Arrange: Set up the wallet and mocks. A usable derivation scope
	// routes signing through the store account secret, whose lookup we
	// fail.
	w, mocks := createUnlockedWalletWithMocks(t)
	scope := waddrmgr.KeyScopeBIP0044

	expectSignerAddressInfoWithKeyScope(
		t, w, mocks, addr, db.PubKeyHash, false, false, pubKey, scope,
	)

	accountNumber := uint32(0)
	mocks.store.On("GetAccountSecret", mock.Anything,
		db.GetAccountSecretQuery{
			WalletID:      w.id,
			Scope:         db.KeyScope(scope),
			AccountNumber: accountNumber,
		}).Return((*db.AccountSecret)(nil), errPrivKeyMock).Once()

	params := &UnlockingScriptParams{
		Tx:        tx,
		Output:    prevOut,
		SigHashes: sigHashes,
		HashType:  txscript.SigHashAll,
	}

	// Act: Attempt to compute the unlocking script.
	_, err = w.ComputeUnlockingScript(t.Context(), params)

	// Assert: Verify error.
	require.ErrorContains(t, err, "privkey error")
}

// TestComputeUnlockingScriptImportedAddress verifies that
// ComputeUnlockingScript signs for an imported address by resolving the private
// key from its own encrypted secret in the store rather than an account
// derivation.
func TestComputeUnlockingScriptImportedAddress(t *testing.T) {
	t.Parallel()

	w, mocks := createUnlockedWalletWithMocks(t)

	// The imported private key is stored per-address; the vault decrypts
	// the stored ciphertext (identity here) to the raw 32-byte key.
	privKey, pubKey := deterministicPrivKey(t)
	encPriv := privKey.Serialize()

	addr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()),
		w.cfg.ChainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	// The store reports the address as imported (no derivation path), so
	// the signer resolves the key through the per-address secret.
	expectStoreAddressInfo(t, w, mocks, addr, &db.AddressInfo{
		ScriptPubKey: pkScript,
		AddrType:     db.WitnessPubKey,
		IsImported:   true,
		PubKey:       pubKey.SerializeCompressed(),
	})
	mocks.store.On("GetAddressSecret", mock.Anything,
		db.GetAddressSecretQuery{
			WalletID:     w.id,
			ScriptPubKey: pkScript,
		}).Return(
		&db.AddressSecret{EncryptedPrivKey: encPriv}, nil,
	).Once()
	mocks.vault.On("Decrypt", waddrmgr.CKTPrivate, encPriv).Return(
		identityDecrypt, nil,
	).Once()

	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	params := &UnlockingScriptParams{
		Tx:         tx,
		InputIndex: 0,
		Output:     prevOut,
		SigHashes:  sigHashes,
		HashType:   txscript.SigHashAll,
	}

	// Act.
	script, err := w.ComputeUnlockingScript(t.Context(), params)
	require.NoError(t, err)

	// Assert: The witness spends the imported P2WKH output.
	require.Nil(t, script.SigScript)
	require.NotNil(t, script.Witness)
	tx.TxIn[0].Witness = script.Witness

	vm, err := txscript.NewEngine(
		prevOut.PkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		sigHashes, prevOut.Value, fetcher,
	)
	require.NoError(t, err)
	require.NoError(t, vm.Execute(), "script execution failed")
}

// TestScriptForOutputScriptClasses verifies that ScriptForOutput resolves each
// stored script class through the same lookup and returns the caller-visible
// script: the redeem script verbatim for P2SH, the witness script verbatim for
// P2WSH, and the decoded leaf script for an imported taproot Tapscript.
func TestScriptForOutputScriptClasses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		addrType db.AddressType

		// build returns the address to resolve, the blob the store
		// persists as the encrypted script, and the script the wallet
		// must hand back.
		build func(*testing.T, *Wallet) (address.Address, []byte,
			[]byte)
	}{{
		name:     "p2sh redeem script",
		addrType: db.ScriptHash,
		build: func(t *testing.T, w *Wallet) (address.Address, []byte,
			[]byte) {

			t.Helper()

			_, pubKey := deterministicPrivKey(t)

			// A representative multisig redeem script; its exact
			// contents are opaque to the wallet, which stores and
			// returns it verbatim.
			redeemScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_1).
				AddData(pubKey.SerializeCompressed()).
				AddOp(txscript.OP_1).
				AddOp(txscript.OP_CHECKMULTISIG).
				Script()
			require.NoError(t, err)

			addr, err := address.NewAddressScriptHash(
				redeemScript, w.cfg.ChainParams,
			)
			require.NoError(t, err)

			return addr, redeemScript, redeemScript
		},
	}, {
		name:     "p2wsh witness script",
		addrType: db.WitnessScript,
		build: func(t *testing.T, w *Wallet) (address.Address, []byte,
			[]byte) {

			t.Helper()

			_, pubKey := deterministicPrivKey(t)

			witnessScript, err := txscript.NewScriptBuilder().
				AddData(pubKey.SerializeCompressed()).
				AddOp(txscript.OP_CHECKSIG).
				Script()
			require.NoError(t, err)

			scriptHash := sha256.Sum256(witnessScript)
			addr, err := address.NewAddressWitnessScriptHash(
				scriptHash[:], w.cfg.ChainParams,
			)
			require.NoError(t, err)

			return addr, witnessScript, witnessScript
		},
	}, {
		name:     "taproot leaf script",
		addrType: db.TaprootPubKey,
		build: func(t *testing.T, w *Wallet) (address.Address, []byte,
			[]byte) {

			t.Helper()

			_, internalKey := deterministicPrivKey(t)

			// A single-leaf taproot script tree and the imported
			// Tapscript committing to it, mirroring
			// ImportTaprootScript's persisted shape.
			leafScript, err := txscript.NewScriptBuilder().
				AddData(schnorr.SerializePubKey(internalKey)).
				AddOp(txscript.OP_CHECKSIG).
				Script()
			require.NoError(t, err)

			leaf := txscript.NewBaseTapLeaf(leafScript)
			tapscript := &waddrmgr.Tapscript{
				Type:   waddrmgr.TapscriptTypeFullTree,
				Leaves: []txscript.TapLeaf{leaf},
				ControlBlock: &txscript.ControlBlock{
					InternalKey: internalKey,
				},
			}

			taprootKey, err := tapscript.TaprootKey()
			require.NoError(t, err)

			addr, err := address.NewAddressTaproot(
				schnorr.SerializePubKey(taprootKey),
				w.cfg.ChainParams,
			)
			require.NoError(t, err)

			// The store persists the TLV-encoded Tapscript as the
			// encrypted script; the identity vault returns it
			// unchanged on decrypt, and ScriptForOutput decodes it
			// back to the leaf script.
			encoded, err := waddrmgr.EncodeTaprootScript(tapscript)
			require.NoError(t, err)

			return addr, encoded, leafScript
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			w, mocks := createUnlockedWalletWithMocks(t)
			addr, stored, want := test.build(t, w)

			script := assertScriptForOutput(
				t, w, mocks, addr, test.addrType, stored,
			)
			require.Equal(t, want, script)
		})
	}
}

// TestScriptForOutputWatchOnlyTaprootSQL exercises the full watch-only taproot
// round trip against a live SQLite store and the production store-backed key
// vault: ImportTaprootScript seals the Tapscript, the SQLite store persists
// that ciphertext, and ScriptForOutput reads it back. This is a read path
// reachable without signing, and it runs through keyvault.NewWalletVault --
// the vault every SQL wallet actually uses -- rather than the legacy manager
// shim, which is what made an earlier version of this test pass against a
// vault configuration production never runs.
//
// The round trip alone cannot pin the wallet-to-store pairing, because a
// store-backed vault resolves both script key types onto its single
// passphrase-derived script key: the seal and the open agree no matter which
// secrecy the store reports. So the persisted secrecy is asserted directly,
// which is what fails if the store's derivation is inverted.
func TestScriptForOutputWatchOnlyTaprootSQL(t *testing.T) {
	t.Parallel()

	// Imported addresses never derive, so a stub derivation is enough.
	deriveAddress := func(context.Context,
		db.AddressDerivationParams) (*db.DerivedAddressData, error) {

		return nil, errDerivationFailed
	}
	store, err := sqlitedb.NewStore(t.Context(), sqlitedb.Config{
		DBPath:        filepath.Join(t.TempDir(), "wallet.sqlite"),
		DeriveAddress: deriveAddress,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	// Real watch-only wallet secrets, so the vault derives its script key
	// from the passphrase exactly as production does.
	passphrase := []byte("watch-only-passphrase")
	secrets, err := keyvault.CreateWalletSecrets(passphrase, nil, true)
	require.NoError(t, err)

	walletInfo, err := store.CreateWallet(
		t.Context(), db.CreateWalletParams{
			Name:                "sql-watch-only-taproot",
			ManagerVersion:      1,
			MasterKeyPrivParams: secrets.MasterPrivParams,
			EncryptedCryptoScriptKey: secrets.
				EncryptedCryptoScriptKey,
			IsWatchOnly: true,
		},
	)
	require.NoError(t, err)

	vault := keyvault.NewWalletVault(store, walletInfo.ID, true)
	require.NoError(t, vault.Unlock(t.Context(), passphrase))
	t.Cleanup(vault.Lock)

	chain := &bwmock.Chain{}
	w := &Wallet{
		store:       store,
		keyVault:    vault,
		cache:       newStoreRuntimeCache(store),
		state:       newWalletState(nil),
		isWatchOnly: true,
		cfg: Config{
			Chain:       chain,
			ChainParams: &chainParams,
		},
		id: walletInfo.ID,
	}
	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())

	tapscript := newTestTapscript(t)
	leafScript := tapscript.Leaves[0].Script

	// Import notifies the chain of the new watch-only address.
	taprootKey, err := tapscript.TaprootKey()
	require.NoError(t, err)
	addr, err := address.NewAddressTaproot(
		schnorr.SerializePubKey(taprootKey), w.cfg.ChainParams,
	)
	require.NoError(t, err)
	chain.On("NotifyReceived", []address.Address{addr}).Return(nil).Once()

	info, err := w.ImportTaprootScript(t.Context(), tapscript)
	require.NoError(t, err)
	require.Equal(t, waddrmgr.TaprootScript, info.AddrType)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// A watch-only wallet still seals script bodies: its passphrase derives
	// a script key even with no private key material. This is the assertion
	// that pins that behaviour, because the round trip below would succeed
	// just as well if the script were stored in the clear.
	encodedScript, err := waddrmgr.EncodeTaprootScript(&tapscript)
	require.NoError(t, err)

	secret, err := store.GetAddressSecret(
		t.Context(), db.GetAddressSecretQuery{
			WalletID:     walletInfo.ID,
			ScriptPubKey: pkScript,
		},
	)
	require.NoError(t, err)
	require.NotEmpty(t, secret.EncryptedScript)
	require.NotEqual(t, encodedScript, secret.EncryptedScript,
		"a watch-only wallet's script must not persist in plaintext")

	// ScriptForOutput reads the imported script back through the same vault
	// that sealed it, returning the revealed leaf script.
	got, err := w.ScriptForOutput(
		t.Context(), wire.TxOut{PkScript: pkScript},
	)
	require.NoError(t, err)
	require.Equal(t, leafScript, got.Script)

	// A locked vault has no key to open the script with: the script key is
	// zeroed on lock even on a watch-only wallet.
	w.keyVault.Lock()

	_, err = w.ScriptForOutput(
		t.Context(), wire.TxOut{PkScript: pkScript},
	)
	require.ErrorIs(t, err, keyvault.ErrVaultLocked)

	chain.AssertExpectations(t)
}

// assertScriptForOutput drives ScriptForOutput for a script-based output whose
// encrypted script decrypts (via the identity vault) to encScript, and returns
// the resolved OutputScriptInfo.Script. It programs the store address lookup as
// a script address and the address-secret lookup as script-only.
//
// Every stored script body reads back through the vault's single script
// operation, so there is no per-address crypto class for the test to select.
func assertScriptForOutput(t *testing.T, w *Wallet, mocks *mockWalletDeps,
	addr address.Address, addrType db.AddressType, encScript []byte) []byte {

	t.Helper()

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// The store owns the address as an imported script address.
	expectStoreAddressInfo(t, w, mocks, addr, &db.AddressInfo{
		ScriptPubKey: pkScript,
		AddrType:     addrType,
		IsImported:   true,
		HasScript:    true,
	})

	// The address secret carries only the encrypted script.
	mocks.store.On("GetAddressSecret", mock.Anything,
		db.GetAddressSecretQuery{
			WalletID:     w.id,
			ScriptPubKey: pkScript,
		}).Return(&db.AddressSecret{
		EncryptedScript: encScript,
	}, nil).Once()

	mocks.vault.On("Decrypt", mock.Anything, encScript).Return(
		identityDecrypt, nil,
	).Once()

	info, err := w.ScriptForOutput(
		t.Context(), wire.TxOut{PkScript: pkScript},
	)
	require.NoError(t, err)

	return info.Script
}

// TestComputeUnlockingScriptFail_Tweak tests failure when the tweaker fails.
func TestComputeUnlockingScriptFail_Tweak(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and mocks. The key is resolved through the
	// store account secret.
	w, mocks := createUnlockedWalletWithMocks(t)
	scope := waddrmgr.KeyScopeBIP0044
	path := waddrmgr.DerivationPath{
		InternalAccount: 0,
		Account:         0,
		Branch:          0,
		Index:           0,
	}
	_, pubKey := expectStoreSignerPrivKey(t, mocks, w.id, scope, path)

	addr, err := address.NewAddressPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// Create fresh mutable state.
	prevOut, tx := createDummyTestTx(pkScript)
	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)

	expectSignerAddressInfoWithKeyScope(
		t, w, mocks, addr, db.PubKeyHash, false, false, pubKey, scope,
	)

	// Define failing tweaker.
	params := &UnlockingScriptParams{
		Tx:        tx,
		Output:    prevOut,
		SigHashes: sigHashes,
		HashType:  txscript.SigHashAll,
		Tweaker: func(*btcec.PrivateKey) (*btcec.PrivateKey, error) {
			return nil, errTweakMock
		},
	}

	// Act: Attempt to compute the unlocking script.
	_, err = w.ComputeUnlockingScript(t.Context(), params)

	// Assert: Verify error.
	require.ErrorContains(t, err, "tweak error")
}

// TestComputeUnlockingScriptFail_UnsupportedAddr tests failure when the
// address type is unsupported.
func TestComputeUnlockingScriptFail_UnsupportedAddr(t *testing.T) {
	t.Parallel()

	// Arrange: Set up keys, address, and transaction.
	_, pubKey := deterministicPrivKey(t)
	addr, err := address.NewAddressPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// Create fresh mutable state.
	prevOut, tx := createDummyTestTx(pkScript)
	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)

	// Arrange: Set up the wallet and mocks.
	w, mocks := createUnlockedWalletWithMocks(t)

	// Mock address store and managed address.
	expectSignerAddressInfo(
		t, w, mocks, addr, db.RawPubKey, false, false, pubKey,
	)

	params := &UnlockingScriptParams{
		Tx:        tx,
		Output:    prevOut,
		SigHashes: sigHashes,
		HashType:  txscript.SigHashAll,
	}

	// Act: Attempt to compute the unlocking script.
	_, err = w.ComputeUnlockingScript(t.Context(), params)

	// Assert: Verify error.
	require.ErrorIs(t, err, ErrUnsupportedAddressType)
}

// TestComputeUnlockingScriptUnknownAddrType tests the default case in
// signAndAssembleScript by using an address with an unknown type.
func TestComputeUnlockingScriptUnknownAddrType(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet, mocks, keys, and transaction.
	w, mocks := createUnlockedWalletWithMocks(t)

	_, pubKey := deterministicPrivKey(t)
	addr, err := address.NewAddressPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()),
		w.cfg.ChainParams,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	pkScript99, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)
	// Mock Store.GetAddress to return an unknown addr type so the
	// addressInfoFromStoreAddress conversion rejects it.
	mocks.store.On("GetAddress", mock.Anything, db.GetAddressQuery{
		WalletID:     w.id,
		ScriptPubKey: pkScript99,
	}).Return(&db.AddressInfo{
		ScriptPubKey: pkScript99,
		AddrType:     db.AddressType(99),
	}, nil).Once()

	fetcher := txscript.NewCannedPrevOutputFetcher(pkScript, 10000)

	params := &UnlockingScriptParams{
		Tx:        tx,
		Output:    prevOut,
		SigHashes: txscript.NewTxSigHashes(tx, fetcher),
		HashType:  txscript.SigHashAll,
	}

	// Act: Attempt to compute the unlocking script.
	_, err = w.ComputeUnlockingScript(t.Context(), params)

	// Assert: Verify that the unknown address type is rejected while building
	// output metadata.
	require.ErrorIs(t, err, ErrUnknownAddrType)
}

// createDummyTestTx creates a dummy transaction for testing purposes.
func createDummyTestTx(pkScript []byte) (*wire.TxOut, *wire.MsgTx) {
	prevOut := wire.NewTxOut(100000, pkScript)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 0}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(90000, nil))

	return prevOut, tx
}

// newSQLAddressSigningWallet returns a started, unlocked wallet whose address
// records are stored in SQLite while signing keys come from legacy waddrmgr.
func newSQLAddressSigningWallet(t *testing.T) (*Wallet, *bwmock.Chain,
	*keyvaultmock.Vault) {

	t.Helper()

	legacyDB, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddressManager(t, legacyDB)
	t.Cleanup(func() {
		addrStore.Close()
	})

	var w *Wallet

	deriveAddress := func(ctx context.Context,
		params db.AddressDerivationParams) (*db.DerivedAddressData, error) {

		return w.deriveAddressData(ctx, params)
	}

	store, err := sqlitedb.NewStore(t.Context(), sqlitedb.Config{
		DBPath:        filepath.Join(t.TempDir(), "wallet.sqlite"),
		DeriveAddress: deriveAddress,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})

	walletInfo, err := store.CreateWallet(
		t.Context(), db.CreateWalletParams{
			Name:                     "sql-signing",
			ManagerVersion:           1,
			EncryptedMasterPrivKey:   []byte{1},
			MasterPubKey:             []byte{2},
			MasterKeyPrivParams:      []byte{3},
			EncryptedCryptoPrivKey:   []byte{4},
			EncryptedCryptoScriptKey: []byte{5},
		},
	)
	require.NoError(t, err)

	_, err = store.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID: walletInfo.ID,
			Scope:    db.KeyScope(waddrmgr.KeyScopeBIP0084),
			Name:     "default",
		}, testAccountDerivationFunc(),
	)
	require.NoError(t, err)

	chain := &bwmock.Chain{}
	vault := &keyvaultmock.Vault{}

	// The signer decrypts account and address secrets through the vault.
	// The SQL store persists the account xprv (and any imported priv key)
	// as the stored ciphertext, so an identity decrypt returns exactly that
	// material. Kept optional so pure address-derivation tests that never
	// sign do not trip the expectation assertions.
	vault.On("Decrypt", waddrmgr.CKTPrivate, mock.Anything).Return(
		identityDecrypt, nil,
	).Maybe()

	w = &Wallet{
		addrStore: addrStore,
		store:     store,
		keyVault:  vault,
		cache:     newStoreRuntimeCache(store),
		state:     newWalletState(nil),
		cfg: Config{
			DB:          legacyDB,
			Chain:       chain,
			ChainParams: &chainParams,
		},
		id: walletInfo.ID,
	}

	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())
	w.state.toUnlocked()

	t.Cleanup(func() {
		chain.AssertExpectations(t)
		vault.AssertExpectations(t)
	})

	return w, chain, vault
}

// newSpendableAddressManager creates and unlocks a deterministic legacy
// waddrmgr manager for signer integration tests.
func newSpendableAddressManager(t *testing.T,
	dbConn walletdb.DB) *waddrmgr.Manager {

	t.Helper()

	const (
		pubPass  = "pub"
		privPass = "priv"
	)

	seed := bytes.Repeat([]byte{0x5A}, hdkeychain.RecommendedSeedLen)
	rootKey, err := hdkeychain.NewMaster(seed, &chainParams)
	require.NoError(t, err)

	var mgr *waddrmgr.Manager

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		err := waddrmgr.Create(
			ns, rootKey, []byte(pubPass), []byte(privPass),
			&chainParams, &waddrmgr.FastScryptOptions, time.Time{},
		)
		if err != nil {
			return err
		}

		mgr, err = waddrmgr.Open(ns, []byte(pubPass), &chainParams)
		if err != nil {
			return err
		}

		return mgr.Unlock(ns, []byte(privPass))
	})
	require.NoError(t, err)

	manager, err := mgr.FetchScopedKeyManager(waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)
	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		_, err := manager.LookupAccount(ns, "default")

		return err
	})
	require.NoError(t, err)

	return mgr
}

// testAccountDerivationFunc returns minimal spendable account material for SQL
// account creation in signer tests.
func testAccountDerivationFunc() db.AccountDerivationFunc {
	return func(_ context.Context, scope db.KeyScope, accountNumber uint32,
		walletIsWatchOnly bool) (*db.DerivedAccountData, error) {

		seed := bytes.Repeat([]byte{0x5A}, hdkeychain.RecommendedSeedLen)

		masterKey, err := hdkeychain.NewMaster(seed, &chainParams)
		if err != nil {
			return nil, fmt.Errorf("new master key: %w", err)
		}

		accountKey, err := deriveBIP44AccountKey(
			masterKey, scope, accountNumber,
		)
		if err != nil {
			return nil, fmt.Errorf("derive account key: %w", err)
		}
		defer accountKey.Zero()

		accountPubKey, err := accountKey.Neuter()
		if err != nil {
			return nil, fmt.Errorf("neuter account key: %w", err)
		}

		data := &db.DerivedAccountData{
			PublicKey:            []byte(accountPubKey.String()),
			MasterKeyFingerprint: 1,
		}
		if !walletIsWatchOnly {
			// Store the account xprv string as the "encrypted"
			// private material. The signing wallet's vault mock
			// decrypts as an identity cipher, so the signer
			// recovers this exact xprv and derives child keys that
			// match the account public key above.
			data.EncryptedPrivateKey = []byte(accountKey.String())
		}

		return data, nil
	}
}

// TestComputeRawSigLegacyP2PKH tests the successful signing of a legacy P2PKH
// input.
func TestComputeRawSigLegacyP2PKH(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and mocks. The signing key is resolved
	// through the store account secret.
	w, mocks := createUnlockedWalletWithMocks(t)

	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}
	_, pubKey := expectStoreSignerPrivKey(
		t, mocks, w.id, path.KeyScope, path.DerivationPath,
	)

	// Create a P2PKH address from the derived leaf public key.
	pubKeyHash := address.Hash160(pubKey.SerializeCompressed())
	addr, err := address.NewAddressPubKeyHash(
		pubKeyHash, w.cfg.ChainParams,
	)
	require.NoError(t, err)

	// Create a previous output and a transaction to spend it.
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	// Create the raw signature parameters.
	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)

	params := &RawSigParams{
		Tx:         tx,
		InputIndex: 0,
		Output:     prevOut,
		SigHashes:  sigHashes,
		HashType:   txscript.SigHashAll,
		Path:       path,
		Details:    LegacySpendDetails{},
	}

	// Act: Compute the raw signature.
	rawSig, err := w.ComputeRawSig(t.Context(), params)
	require.NoError(t, err)

	// Assert: Verify that the signature is valid.
	sigScript, err := txscript.NewScriptBuilder().
		AddData(rawSig).
		AddData(pubKey.SerializeCompressed()).
		Script()
	require.NoError(t, err)

	tx.TxIn[0].SignatureScript = sigScript

	// The signature is valid if the script engine executes without error.
	vm, err := txscript.NewEngine(
		prevOut.PkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		sigHashes, prevOut.Value, txscript.NewCannedPrevOutputFetcher(
			prevOut.PkScript, prevOut.Value,
		),
	)
	require.NoError(t, err)
	require.NoError(t, vm.Execute(), "signature verification failed")
}

// TestComputeRawSigLegacyP2SH tests the signing of a legacy P2SH input.
func TestComputeRawSigLegacyP2SH(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet with mocks. The signing key is resolved
	// through the store account secret. P2SH addresses use BIP0049 scope.
	w, mocks := createUnlockedWalletWithMocks(t)
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0049Plus}
	_, pubKey := expectStoreSignerPrivKey(
		t, mocks, w.id, path.KeyScope, path.DerivationPath,
	)

	// Create a P2SH redeem script. This involves pushing the public key
	// and the CHECKSIG opcode.
	redeemScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_DATA_33).
		AddData(pubKey.SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	// Create the P2SH address corresponding to the redeem script hash.
	addr, err := address.NewAddressScriptHash(
		redeemScript, w.cfg.ChainParams,
	)
	require.NoError(t, err)

	// Create the Pay-To-Addr script (P2SH script) which will be the
	// pkScript of the previous output.
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// Create a dummy transaction and a previous output to spend.
	prevOut, tx := createDummyTestTx(pkScript)

	// Prepare the inputs for the signing operation.
	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)

	params := &RawSigParams{
		Tx:         tx,
		InputIndex: 0,
		Output:     prevOut,
		SigHashes:  sigHashes,
		HashType:   txscript.SigHashAll,
		Path:       path,
		Details: LegacySpendDetails{
			RedeemScript: redeemScript,
		},
	}

	// Act: Compute the raw signature using the wallet.
	rawSig, err := w.ComputeRawSig(t.Context(), params)

	// Assert: Verify that no error occurred and a signature was generated.
	require.NoError(t, err)
	require.NotEmpty(t, rawSig)
}

// TestComputeRawSigSegwitV0 tests the successful signing of a SegWit v0 P2WKH
// input.
func TestComputeRawSigSegwitV0(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and mocks. The signing key is resolved
	// through the store account secret.
	w, mocks := createUnlockedWalletWithMocks(t)

	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}
	_, pubKey := expectStoreSignerPrivKey(
		t, mocks, w.id, path.KeyScope, path.DerivationPath,
	)

	// Create a P2WKH address from the derived leaf public key.
	pubKeyHash := address.Hash160(pubKey.SerializeCompressed())
	addr, err := address.NewAddressWitnessPubKeyHash(
		pubKeyHash, w.cfg.ChainParams,
	)
	require.NoError(t, err)

	// Create a previous output and a transaction to spend it.
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	// Create the raw signature parameters.
	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	witnessScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	params := &RawSigParams{
		Tx:         tx,
		InputIndex: 0,
		Output:     prevOut,
		SigHashes:  sigHashes,
		HashType:   txscript.SigHashAll,
		Path:       path,
		Details: SegwitV0SpendDetails{
			WitnessScript: witnessScript,
		},
	}

	// Act: Compute the raw signature.
	rawSig, err := w.ComputeRawSig(t.Context(), params)
	require.NoError(t, err)

	// Assert: Verify that the signature is valid.
	// We need to append the sighash type to the raw signature.
	rawSig = append(rawSig, byte(txscript.SigHashAll))
	tx.TxIn[0].Witness = wire.TxWitness{
		rawSig, pubKey.SerializeCompressed(),
	}

	// The signature is valid if the script engine executes without error.
	vm, err := txscript.NewEngine(
		prevOut.PkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		sigHashes, prevOut.Value, txscript.NewCannedPrevOutputFetcher(
			prevOut.PkScript, prevOut.Value,
		),
	)
	require.NoError(t, err)
	require.NoError(t, vm.Execute(), "signature verification failed")
}

// TestComputeRawSigTaprootKeySpendPath tests the successful signing of a
// Taproot P2TR input using the key-path spend.
func TestComputeRawSigTaprootKeySpendPath(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and mocks. The signing key is resolved
	// through the store account secret.
	w, mocks := createUnlockedWalletWithMocks(t)

	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0086}
	_, internalKey := expectStoreSignerPrivKey(
		t, mocks, w.id, path.KeyScope, path.DerivationPath,
	)

	// Create a P2TR address from the derived leaf public key.
	addr, err := address.NewAddressTaproot(
		schnorr.SerializePubKey(
			txscript.ComputeTaprootOutputKey(internalKey, nil),
		), w.cfg.ChainParams,
	)
	require.NoError(t, err)

	// Create a previous output and a transaction to spend it.
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	// Create the raw signature parameters.
	fetcher := txscript.NewMultiPrevOutFetcher(
		map[wire.OutPoint]*wire.TxOut{
			{Index: 0}: prevOut,
		},
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)

	params := &RawSigParams{
		Tx:         tx,
		InputIndex: 0,
		Output:     prevOut,
		SigHashes:  sigHashes,
		HashType:   txscript.SigHashDefault,
		Path:       path,
		Details: TaprootSpendDetails{
			SpendPath: KeyPathSpend,
		},
	}

	// Act: Compute the raw signature.
	rawSig, err := w.ComputeRawSig(t.Context(), params)
	require.NoError(t, err)

	// Assert: Verify that the signature is valid.
	tx.TxIn[0].Witness = wire.TxWitness{rawSig}
	vm, err := txscript.NewEngine(
		pkScript, tx, 0, txscript.StandardVerifyFlags, nil, sigHashes,
		prevOut.Value, txscript.NewCannedPrevOutputFetcher(
			prevOut.PkScript, prevOut.Value,
		),
	)
	require.NoError(t, err)
	require.NoError(t, vm.Execute(), "signature verification failed")
}

// TestComputeRawSigTaprootScriptPath tests the successful signing of a Taproot
// P2TR input using the script-path spend.
func TestComputeRawSigTaprootScriptPath(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and mocks. The signing key is resolved
	// through the store account secret.
	w, mocks := createUnlockedWalletWithMocks(t)

	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0086}
	_, internalKey := expectStoreSignerPrivKey(
		t, mocks, w.id, path.KeyScope, path.DerivationPath,
	)

	// Create a script to spend, committing to the derived leaf key.
	script, err := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(internalKey)).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	leaf := txscript.NewBaseTapLeaf(script)
	tapScriptTree := txscript.AssembleTaprootScriptTree(leaf)
	rootHash := tapScriptTree.RootNode.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(internalKey, rootHash[:])

	// Create a P2TR address from the output key.
	addr, err := address.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey), w.cfg.ChainParams,
	)
	require.NoError(t, err)

	// Create a previous output and a transaction to spend it.
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	// Create the raw signature parameters.
	fetcher := txscript.NewMultiPrevOutFetcher(
		map[wire.OutPoint]*wire.TxOut{
			{Index: 0}: prevOut,
		},
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)

	params := &RawSigParams{
		Tx:         tx,
		InputIndex: 0,
		Output:     prevOut,
		SigHashes:  sigHashes,
		HashType:   txscript.SigHashDefault,
		Path:       path,
		Details: TaprootSpendDetails{
			SpendPath:     ScriptPathSpend,
			WitnessScript: script,
		},
	}

	// Act: Compute the raw signature.
	rawSig, err := w.ComputeRawSig(t.Context(), params)
	require.NoError(t, err)

	// Assert: Verify that the signature is valid.
	// For script path, we need the control block.
	ctrlBlock := tapScriptTree.LeafMerkleProofs[0].ToControlBlock(
		internalKey,
	)
	ctrlBlockBytes, err := ctrlBlock.ToBytes()
	require.NoError(t, err)

	tx.TxIn[0].Witness = wire.TxWitness{
		rawSig, script, ctrlBlockBytes,
	}
	vm, err := txscript.NewEngine(
		pkScript, tx, 0, txscript.StandardVerifyFlags, nil, sigHashes,
		prevOut.Value, txscript.NewCannedPrevOutputFetcher(
			prevOut.PkScript, prevOut.Value,
		),
	)
	require.NoError(t, err)
	require.NoError(t, vm.Execute(), "signature verification failed")
}

// TestComputeRawSigFail tests various failure modes of ComputeRawSig.
func TestComputeRawSigFail(t *testing.T) {
	t.Parallel()

	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}
	prevOut := &wire.TxOut{PkScript: []byte{0x00}}
	tx := wire.NewMsgTx(2)

	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)

	// storeSecretQuery builds the account-secret query the signer issues
	// for the default account under the given scope.
	storeSecretQuery := func(w *Wallet,
		scope waddrmgr.KeyScope) db.GetAccountSecretQuery {

		accountNumber := uint32(0)

		return db.GetAccountSecretQuery{
			WalletID:      w.id,
			Scope:         db.KeyScope(scope),
			AccountNumber: accountNumber,
		}
	}

	// This subtest ensures that if the store account-secret lookup fails
	// during the raw signature computation, the error is correctly
	// propagated.
	t.Run("Fetch Address Fail", func(t *testing.T) {
		t.Parallel()
		w, mocks := createUnlockedWalletWithMocks(t)
		mocks.store.On("GetAccountSecret", mock.Anything,
			storeSecretQuery(w, path.KeyScope)).Return(
			(*db.AccountSecret)(nil), errManagerNotFound,
		).Once()

		params := &RawSigParams{
			Tx:        tx,
			Output:    prevOut,
			SigHashes: sigHashes,
			HashType:  txscript.SigHashAll,
			Path:      path,
			Details:   LegacySpendDetails{},
		}

		_, err := w.ComputeRawSig(t.Context(), params)
		require.ErrorIs(t, err, errManagerNotFound)
	})

	// This subtest ensures that a watch-only signing account yields the
	// watch-only error during raw signature computation.
	t.Run("PrivKey Fail", func(t *testing.T) {
		t.Parallel()
		w, mocks := createUnlockedWalletWithMocks(t)
		mocks.store.On("GetAccountSecret", mock.Anything,
			storeSecretQuery(w, path.KeyScope)).Return(
			&db.AccountSecret{}, nil,
		).Once()

		params := &RawSigParams{
			Tx:        tx,
			Output:    prevOut,
			SigHashes: sigHashes,
			HashType:  txscript.SigHashAll,
			Path:      path,
			Details:   LegacySpendDetails{},
		}

		_, err := w.ComputeRawSig(t.Context(), params)
		require.ErrorIs(t, err, ErrWatchOnlyAccount)
	})

	// This subtest verifies that if the private key tweaking function
	// returns an error, the raw signature computation correctly propagates
	// that error.
	t.Run("Tweak Fail", func(t *testing.T) {
		t.Parallel()
		w, mocks := createUnlockedWalletWithMocks(t)
		expectStoreSignerPrivKey(
			t, mocks, w.id, path.KeyScope, path.DerivationPath,
		)

		params := &RawSigParams{
			Tx:        tx,
			Output:    prevOut,
			SigHashes: sigHashes,
			HashType:  txscript.SigHashAll,
			Path:      path,
			Details:   LegacySpendDetails{},
			Tweaker: func(*btcec.PrivateKey) (
				*btcec.PrivateKey, error) {

				return nil, errTweakMock
			},
		}

		_, err := w.ComputeRawSig(t.Context(), params)
		require.ErrorContains(t, err, "tweak error")
	})

	// This subtest ensures that if the underlying `Sign` method of the
	// spend details returns an error, the raw signature computation
	// correctly propagates that error.
	t.Run("Sign Fail", func(t *testing.T) {
		t.Parallel()
		w, mocks := createUnlockedWalletWithMocks(t)
		leafPriv, _ := expectStoreSignerPrivKey(
			t, mocks, w.id, path.KeyScope, path.DerivationPath,
		)

		params := &RawSigParams{
			Tx:        tx,
			Output:    prevOut,
			SigHashes: sigHashes,
			HashType:  txscript.SigHashAll,
			Path:      path,
			Details:   LegacySpendDetails{},
		}
		mockDetails := &mockSpendDetails{}
		params.Details = mockDetails

		// The signer derives its own leaf key; match on the value it
		// resolves rather than object identity.
		mockDetails.On("Sign", params, mock.MatchedBy(
			func(pk *btcec.PrivateKey) bool {
				return pk.Key.Equals(&leafPriv.Key)
			})).Return((RawSignature)(nil), errSignMock)
		_, err := w.ComputeRawSig(t.Context(), params)
		require.ErrorContains(t, err, "sign error")
		mockDetails.AssertExpectations(t)
	})

	// This subtest verifies that an error is returned when an unsupported
	// Taproot spend path is provided, ensuring robust error handling for
	// invalid configurations.
	t.Run("Invalid Taproot Path", func(t *testing.T) {
		t.Parallel()
		w, mocks := createUnlockedWalletWithMocks(t)

		scope := waddrmgr.KeyScopeBIP0086
		expectStoreSignerPrivKey(
			t, mocks, w.id, scope, waddrmgr.DerivationPath{},
		)

		params := &RawSigParams{
			Tx:   wire.NewMsgTx(2),
			Path: BIP32Path{KeyScope: scope},
			Details: TaprootSpendDetails{
				SpendPath: TaprootSpendPath(99), // Invalid path
			},
		}

		_, err := w.ComputeRawSig(t.Context(), params)
		require.ErrorIs(t, err, ErrUnknownSignMethod)
	})

	// This subtest verifies that if the SegWit v0 signing process fails
	// (e.g., due to invalid parameters like an invalid hash type), the
	// error is correctly propagated.
	t.Run("Segwit Sign Fail", func(t *testing.T) {
		t.Parallel()
		w, mocks := createUnlockedWalletWithMocks(t)
		expectStoreSignerPrivKey(
			t, mocks, w.id, path.KeyScope, path.DerivationPath,
		)

		params := &RawSigParams{
			Tx:        tx,
			Output:    prevOut,
			SigHashes: sigHashes,
			HashType:  0xff,
			Path:      path,
			Details: SegwitV0SpendDetails{
				WitnessScript: []byte{},
			},
		}

		_, err := w.ComputeRawSig(t.Context(), params)
		require.Error(t, err)
	})

	// This subtest verifies that if the Taproot KeyPath signing process
	// fails (e.g., due to invalid parameters), the error is correctly
	// propagated.
	t.Run("Taproot KeyPath Sign Fail", func(t *testing.T) {
		t.Parallel()
		w, mocks := createUnlockedWalletWithMocks(t)
		expectStoreSignerPrivKey(
			t, mocks, w.id, path.KeyScope, path.DerivationPath,
		)

		params := &RawSigParams{
			Tx:        tx,
			Output:    prevOut,
			SigHashes: sigHashes,
			HashType:  0xff,
			Path:      path,
			Details:   TaprootSpendDetails{SpendPath: KeyPathSpend},
		}

		_, err := w.ComputeRawSig(t.Context(), params)
		require.Error(t, err)
	})

	// This subtest verifies that if the Taproot ScriptPath signing process
	// fails (e.g., due to invalid parameters), the error is correctly
	// propagated.
	t.Run("Taproot ScriptPath Sign Fail", func(t *testing.T) {
		t.Parallel()
		w, mocks := createUnlockedWalletWithMocks(t)
		expectStoreSignerPrivKey(
			t, mocks, w.id, path.KeyScope, path.DerivationPath,
		)

		params := &RawSigParams{
			Tx:        tx,
			Output:    prevOut,
			SigHashes: sigHashes,
			HashType:  0xff,
			Path:      path,
			Details: TaprootSpendDetails{
				SpendPath:     ScriptPathSpend,
				WitnessScript: []byte{0x51},
			},
		}

		_, err := w.ComputeRawSig(t.Context(), params)
		require.Error(t, err)
	})
}

// TestDerivePrivKeySuccess tests the successful derivation of a private key.
func TestDerivePrivKeySuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet with mocks and a derivation path. The key
	// is resolved through the store account secret.
	w, mocks := createUnlockedWalletWithMocks(t)

	path := BIP32Path{
		KeyScope: waddrmgr.KeyScopeBIP0084,
		DerivationPath: waddrmgr.DerivationPath{
			InternalAccount: 0,
			Branch:          0,
			Index:           0,
		},
	}
	leafPriv, _ := expectStoreSignerPrivKey(
		t, mocks, w.id, path.KeyScope, path.DerivationPath,
	)

	// Act: Derive the private key.
	derivedKey, err := w.DerivePrivKey(t.Context(), path)

	// Assert: Check that the correct key is returned without error.
	require.NoError(t, err)
	require.Equal(t, leafPriv.Serialize(), derivedKey.Serialize())
}

// TestDerivePrivKeyFails tests the failure case where the store account-secret
// lookup fails.
func TestDerivePrivKeyFails(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and a test path. Configure the store to
	// fail the account-secret lookup.
	w, mocks := createUnlockedWalletWithMocks(t)
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}

	accountNumber := path.DerivationPath.InternalAccount
	mocks.store.On("GetAccountSecret", mock.Anything,
		db.GetAccountSecretQuery{
			WalletID:      w.id,
			Scope:         db.KeyScope(path.KeyScope),
			AccountNumber: accountNumber,
		}).Return((*db.AccountSecret)(nil), errManagerNotFound).Once()

	// Act: Attempt to derive the private key.
	_, err := w.DerivePrivKey(t.Context(), path)

	// Assert: Check that the error is propagated correctly.
	require.ErrorIs(t, err, errManagerNotFound)
}

// TestGetPrivKeyForAddressSuccess tests the successful retrieval of a private
// key for a derived address through the store account secret.
func TestGetPrivKeyForAddressSuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and mocks. The key is resolved through the
	// store account secret.
	w, mocks := createUnlockedWalletWithMocks(t)
	scope := waddrmgr.KeyScopeBIP0084
	path := waddrmgr.DerivationPath{}
	leafPriv, pubKey := expectStoreSignerPrivKey(
		t, mocks, w.id, scope, path,
	)

	// Create a P2WKH address from the derived leaf public key.
	addr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()),
		w.cfg.ChainParams,
	)
	require.NoError(t, err)

	// The store owns the address with a usable derivation scope, so the
	// signer resolves the key through the account secret.
	expectSignerAddressInfoWithKeyScope(
		t, w, mocks, addr, db.WitnessPubKey, false, false, pubKey,
		scope,
	)

	// Act: Get the private key for the address.
	retrievedKey, err := w.GetPrivKeyForAddress(t.Context(), addr)

	// Assert: Check that the correct key is returned.
	require.NoError(t, err)
	require.Equal(t, leafPriv.Serialize(), retrievedKey.Serialize())
}

// TestGetPrivKeyForAddressFail tests the failure cases for retrieval of a
// private key by address through the store.
func TestGetPrivKeyForAddressFail(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and mocks.
	w, mocks := createUnlockedWalletWithMocks(t)
	addr, err := address.NewAddressPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	query := db.GetAddressQuery{
		WalletID:     w.id,
		ScriptPubKey: pkScript,
	}

	// Case 1: An unexpected store error surfaces, not masked.
	mocks.store.On("GetAddress", mock.Anything, query).Return(
		(*db.AddressInfo)(nil), errManagerNotFound,
	).Once()

	_, err = w.GetPrivKeyForAddress(t.Context(), addr)
	require.ErrorIs(t, err, errManagerNotFound)

	// Case 2: The address is not owned by the wallet, so it has no
	// associated private key.
	mocks.store.On("GetAddress", mock.Anything, query).Return(
		(*db.AddressInfo)(nil), db.ErrAddressNotFound,
	).Once()

	_, err = w.GetPrivKeyForAddress(t.Context(), addr)
	require.ErrorIs(t, err, ErrNoAssocPrivateKey)
}

// TestGetPrivKeyForAddressImportedNoPrivKey verifies that requesting the
// private key for a watch-only imported address (no stored private material)
// returns ErrNoAssocPrivateKey.
func TestGetPrivKeyForAddressImportedNoPrivKey(t *testing.T) {
	t.Parallel()

	w, mocks := createUnlockedWalletWithMocks(t)
	_, pubKey := deterministicPrivKey(t)

	addr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()),
		w.cfg.ChainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// The address is owned but imported (no derivation path).
	expectStoreAddressInfo(t, w, mocks, addr, &db.AddressInfo{
		ScriptPubKey: pkScript,
		AddrType:     db.WitnessPubKey,
		IsImported:   true,
		PubKey:       pubKey.SerializeCompressed(),
	})

	// The imported address carries no private-key material.
	mocks.store.On("GetAddressSecret", mock.Anything,
		db.GetAddressSecretQuery{
			WalletID:     w.id,
			ScriptPubKey: pkScript,
		}).Return((*db.AddressSecret)(nil), db.ErrSecretNotFound).Once()

	// Act + Assert.
	_, err = w.GetPrivKeyForAddress(t.Context(), addr)
	require.ErrorIs(t, err, ErrNoAssocPrivateKey)
}

// TestDerivePrivKeyFail tests failure modes of DerivePrivKey through the
// store-routed key path.
func TestDerivePrivKeyFail(t *testing.T) {
	t.Parallel()

	w, mocks := createUnlockedWalletWithMocks(t)
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}

	accountNumber := path.DerivationPath.InternalAccount
	query := db.GetAccountSecretQuery{
		WalletID:      w.id,
		Scope:         db.KeyScope(path.KeyScope),
		AccountNumber: accountNumber,
	}

	// Test Case 1: The account-secret lookup fails with an unexpected
	// error, which is propagated.
	mocks.store.On("GetAccountSecret", mock.Anything, query).Return(
		(*db.AccountSecret)(nil), errPrivKeyMock,
	).Once()

	_, err := w.DerivePrivKey(t.Context(), path)
	require.ErrorIs(t, err, errPrivKeyMock)

	// Test Case 2: The signing account is watch-only.
	mocks.store.On("GetAccountSecret", mock.Anything, query).Return(
		&db.AccountSecret{}, nil,
	).Once()

	_, err = w.DerivePrivKey(t.Context(), path)
	require.ErrorIs(t, err, ErrWatchOnlyAccount)
}

// TestECDHFail tests failure modes of ECDH through the store-routed key path.
func TestECDHFail(t *testing.T) {
	t.Parallel()

	w, mocks := createUnlockedWalletWithMocks(t)
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}
	remoteKey, _ := btcec.NewPrivateKey()

	accountNumber := path.DerivationPath.InternalAccount
	query := db.GetAccountSecretQuery{
		WalletID:      w.id,
		Scope:         db.KeyScope(path.KeyScope),
		AccountNumber: accountNumber,
	}

	// Test Case 1: The account-secret lookup fails with an unexpected
	// error, which is propagated.
	mocks.store.On("GetAccountSecret", mock.Anything, query).Return(
		(*db.AccountSecret)(nil), errPrivKeyMock,
	).Once()

	_, err := w.ECDH(t.Context(), path, remoteKey.PubKey())
	require.ErrorIs(t, err, errPrivKeyMock)

	// Test Case 2: The signing account is watch-only.
	mocks.store.On("GetAccountSecret", mock.Anything, query).Return(
		&db.AccountSecret{}, nil,
	).Once()

	_, err = w.ECDH(t.Context(), path, remoteKey.PubKey())
	require.ErrorIs(t, err, ErrWatchOnlyAccount)
}

// TestSignDigestLocked tests that SignDigest fails when the wallet is locked.
func TestSignDigestLocked(t *testing.T) {
	t.Parallel()

	// Arrange: Create a locked wallet.
	w, _ := createStartedWalletWithMocks(t)
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}
	intent := &SignDigestIntent{
		Digest:  make([]byte, 32),
		SigType: SigTypeECDSA,
	}

	// Act: Call SignDigest.
	_, err := w.SignDigest(t.Context(), path, intent)

	// Assert: Check for forbidden/locked error.
	require.ErrorIs(t, err, ErrStateForbidden)
}
