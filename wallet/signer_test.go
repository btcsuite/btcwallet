// Copyright (c) 2020 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
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

// TestDerivePubKeySuccess tests the successful derivation of a public key.
func TestDerivePubKeySuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet with mocks, a test key, and a
	// derivation path.
	w, mocks := createUnlockedWalletWithMocks(t)
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	path := BIP32Path{
		KeyScope: waddrmgr.KeyScopeBIP0084,
		DerivationPath: waddrmgr.DerivationPath{
			InternalAccount: 0,
			Branch:          0,
			Index:           0,
		},
	}

	// Set up the mock account manager and the mock address that will be
	// returned by the derivation call.
	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return(mocks.accountManager, nil).Once()
	mocks.accountManager.On(
		"DeriveFromKeyPath", mock.Anything, path.DerivationPath,
	).Return(mocks.pubKeyAddr, nil).Once()
	mocks.pubKeyAddr.On("PubKey").Return(pubKey).Once()

	// Act: Derive the public key.
	derivedKey, err := w.DerivePubKey(t.Context(), path)

	// Assert: Check that the correct key is returned without error.
	require.NoError(t, err)
	require.True(t, pubKey.IsEqual(derivedKey))
}

// TestDerivePubKeyFetchManagerFails tests the failure case where the scoped
// key manager cannot be fetched.
func TestDerivePubKeyFetchManagerFails(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and a test path. Configure the mock
	// addrStore to return an error when fetching the key manager.
	w, mocks := createUnlockedWalletWithMocks(t)
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}

	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return((*mockAccountStore)(nil), errManagerNotFound).Once()

	// Act: Attempt to derive the public key.
	_, err := w.DerivePubKey(t.Context(), path)

	// Assert: Check that the error is propagated correctly.
	require.ErrorIs(t, err, errManagerNotFound)
	mocks.addrStore.AssertExpectations(t)
}

// TestDerivePubKeyDeriveFails tests the failure case where the key derivation
// from the path fails.
func TestDerivePubKeyDeriveFails(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet, mocks, and a test path. Configure the
	// mock account manager to return an error on derivation.
	w, mocks := createUnlockedWalletWithMocks(t)
	path := BIP32Path{
		KeyScope: waddrmgr.KeyScopeBIP0084,
		DerivationPath: waddrmgr.DerivationPath{
			InternalAccount: 0,
			Branch:          0,
			Index:           0,
		},
	}

	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return(mocks.accountManager, nil).Once()
	mocks.accountManager.On(
		"DeriveFromKeyPath", mock.Anything, path.DerivationPath,
	).Return((*mockManagedPubKeyAddr)(nil), errDerivationFailed).Once()

	// Act: Attempt to derive the public key.
	_, err := w.DerivePubKey(t.Context(), path)

	// Assert: Check that the error is propagated correctly.
	require.ErrorIs(t, err, errDerivationFailed)
}

// TestDerivePubKeyNotPubKeyAddr tests the failure case where the derived
// address is not a public key address.
func TestDerivePubKeyNotPubKeyAddr(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and mocks. Configure the mock derivation
	// to return a managed address that is NOT a ManagedPubKeyAddress.
	w, mocks := createUnlockedWalletWithMocks(t)
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}

	// We need a valid address for the error message.
	addr, err := btcutil.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	require.NoError(t, err)

	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return(mocks.accountManager, nil).Once()
	mocks.accountManager.On("DeriveFromKeyPath",
		mock.Anything, mock.Anything,
	).Return(mocks.addr, nil).Once()
	mocks.addr.On("Address").Return(addr).Once()

	// Act: Attempt to derive the public key.
	_, err = w.DerivePubKey(t.Context(), path)

	// Assert: Check that the specific ErrNotPubKeyAddress is returned.
	require.ErrorIs(t, err, ErrNotPubKeyAddress)
	require.ErrorContains(t, err, "addr "+addr.String())
}

// TestECDHSuccess tests the successful ECDH key exchange.
func TestECDHSuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet, mocks, and test keys.
	w, mocks := createUnlockedWalletWithMocks(t)

	// Use a hardcoded private key for deterministic test results.
	privKey, _ := deterministicPrivKey(t)

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

	// Configure the full mock chain to return the test private key.
	//
	// NOTE: We must use a copy since the ECDH method will zero out the key.
	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())

	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return(mocks.accountManager, nil).Once()
	mocks.accountManager.On(
		"DeriveFromKeyPath", mock.Anything, path.DerivationPath,
	).Return(mocks.pubKeyAddr, nil).Once()
	mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil).Once()

	// Act: Perform the ECDH operation.
	sharedSecret, err := w.ECDH(t.Context(), path, remotePubKey)

	// Assert: Check that the correct shared secret is returned.
	require.NoError(t, err)

	// Calculate the expected secret independently to verify.
	expectedSecret := btcec.GenerateSharedSecret(privKey, remotePubKey)

	var expectedSecretArray [32]byte
	copy(expectedSecretArray[:], expectedSecret)

	require.Equal(t, expectedSecretArray, sharedSecret)

	// Finally, assert that the private key is zeroed out.
	require.Equal(t, byte(0), privKeyCopy.Serialize()[0])
}

// TestECDHFails tests the failure case where the key derivation fails during
// an ECDH operation.
func TestECDHFails(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and configure the mock addrStore to return
	// an error.
	w, mocks := createUnlockedWalletWithMocks(t)
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}

	remoteKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	remotePubKey := remoteKey.PubKey()

	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return((*mockAccountStore)(nil), errDerivationFailed).Once()

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

// expectDerivedSignerPrivKey wires the signer-private key lookup path for a
// derived managed pubkey address.
func expectDerivedSignerPrivKey(t *testing.T, mocks *mockWalletDeps,
	scope waddrmgr.KeyScope, path waddrmgr.DerivationPath,
	privKey *btcec.PrivateKey) {

	t.Helper()

	mocks.pubKeyAddr.On("Imported").Return(false).Once()
	mocks.pubKeyAddr.On("DerivationInfo").Return(scope, path, true).Once()
	mocks.addrStore.On("FetchScopedKeyManager", scope).
		Return(mocks.accountManager, nil).Once()
	mocks.accountManager.On("DeriveFromKeyPathCache", path).
		Return(privKey, nil).Once()
}

// TestSignDigest tests the signing of a message digest with different signature
// types.
func TestSignDigest(t *testing.T) {
	t.Parallel()

	// We'll use a common set of parameters for all signing test cases to
	// ensure the only variable is the signing intent itself.
	privKey, pubKey := deterministicPrivKey(t)
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
		// the signing intent.
		verify func(t *testing.T, sig Signature,
			pubKey *btcec.PublicKey)
	}{
		{
			name: "ECDSA success",
			intent: &SignDigestIntent{
				Digest:     msgHash,
				SigType:    SigTypeECDSA,
				CompactSig: false,
			},
			verify: func(t *testing.T, sig Signature,
				pubKey *btcec.PublicKey) {

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
				pubKey *btcec.PublicKey) {

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
				pubKey *btcec.PublicKey) {

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
				pubKey *btcec.PublicKey) {

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

			// Arrange: Set up a mock wallet that will return our
			// deterministic private key for the specified
			// derivation path. This allows us to test the signing
			// logic in isolation.
			w, mocks := createUnlockedWalletWithMocks(t)

			// Configure the full mock chain to return the test
			// private key.
			//
			// NOTE: We must use a copy since the ECDH method will
			// zero out the key.
			privKeyCopy, _ := btcec.PrivKeyFromBytes(
				privKey.Serialize(),
			)

			mocks.addrStore.On(
				"FetchScopedKeyManager", path.KeyScope,
			).Return(mocks.accountManager, nil).Once()
			mocks.accountManager.On(
				"DeriveFromKeyPath", mock.Anything,
				path.DerivationPath,
			).Return(mocks.pubKeyAddr, nil).Once()
			mocks.pubKeyAddr.On("PrivKey").Return(
				privKeyCopy, nil,
			).Once()

			// Act: Attempt to sign the message with the wallet.
			sig, err := w.SignDigest(t.Context(), path, tc.intent)

			// Assert: Verify that the signature was created
			// successfully and is valid for the given public key.
			// We also assert that the private key was cleared from
			// memory after the operation.
			require.NoError(t, err)
			tc.verify(t, sig, pubKey)
			require.Equal(t, byte(0), privKeyCopy.Serialize()[0])
		})
	}
}

// TestSignDigestFail tests failure modes of SignDigest.
func TestSignDigestFail(t *testing.T) {
	t.Parallel()

	w, mocks := createUnlockedWalletWithMocks(t)
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}

	digest := make([]byte, 32)
	intent := &SignDigestIntent{Digest: digest}

	// Test Case 1: Fetching the key manager fails.
	// We expect an `errManagerNotFound` error to be returned.
	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return((*mockAccountStore)(nil), errManagerNotFound).Once()

	_, err := w.SignDigest(t.Context(), path, intent)
	require.ErrorIs(t, err, errManagerNotFound)

	// Test Case 2: Obtaining the private key for signing fails.
	// We expect a `privkey error` to be returned.
	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return(mocks.accountManager, nil).Once()
	mocks.accountManager.On("DeriveFromKeyPath",
		mock.Anything, mock.Anything).
		Return(mocks.pubKeyAddr, nil).Once()
	mocks.pubKeyAddr.On("PrivKey").Return((*btcec.PrivateKey)(nil),
		errPrivKeyMock).Once()

	_, err = w.SignDigest(t.Context(), path, intent)
	require.ErrorContains(t, err, "privkey error")
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

	// Arrange: Set up the wallet, keys, and a dummy transaction that will
	// be used to spend the P2PKH output.
	w, mocks := createUnlockedWalletWithMocks(t)
	privKey, pubKey := deterministicPrivKey(t)

	// Create a P2PKH address and the corresponding previous output script.
	// This is the output we want to create an unlocking script for.
	addr, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()),
		w.cfg.ChainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	// The wallet needs to be able to find the private key for the given
	// address. We mock the address store to return a mock address that,
	// when queried, will provide the private key for signing. This
	// simulates a real scenario where the wallet's address manager would
	// fetch the key from the database.
	mocks.addrStore.On("Address",
		mock.Anything, addr,
	).Return(mocks.pubKeyAddr, nil).Twice()
	mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.PubKeyHash).Twice()

	// Configure the full mock chain to return the test private key.
	//
	// NOTE: We must use a copy since the ECDH method will zero out the key.
	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())
	expectDerivedSignerPrivKey(
		t, mocks, waddrmgr.KeyScopeBIP0044, waddrmgr.DerivationPath{
			InternalAccount: 0,
			Account:         0,
			Branch:          0,
			Index:           0,
		}, privKeyCopy,
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

	// Finally, we ensure that the private key was not mutated during the
	// signing process.
	require.Equal(t, byte(0), privKeyCopy.Serialize()[0])
}

// TestComputeUnlockingScriptP2WKH tests that the wallet can generate a valid
// unlocking script for a P2WKH output.
func TestComputeUnlockingScriptP2WKH(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet, keys, and a dummy transaction that will
	// be used to spend the P2WKH output.
	w, mocks := createUnlockedWalletWithMocks(t)
	privKey, pubKey := deterministicPrivKey(t)

	// Create a P2WKH address and the corresponding previous output script.
	addr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()),
		w.cfg.ChainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	// The wallet needs to be able to find the private key for the given
	// address. We mock the address store to return a mock address that,
	// when queried, will provide the private key for signing.
	mocks.addrStore.On("Address",
		mock.Anything, addr,
	).Return(mocks.pubKeyAddr, nil).Twice()
	mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey).Twice()

	// Configure the full mock chain to return the test private key.
	//
	// NOTE: We must use a copy since the ECDH method will zero out the key.
	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())
	expectDerivedSignerPrivKey(
		t, mocks, waddrmgr.KeyScopeBIP0084, waddrmgr.DerivationPath{
			InternalAccount: 0,
			Account:         0,
			Branch:          0,
			Index:           0,
		}, privKeyCopy,
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

	// Finally, we ensure that the private key was not mutated during the
	// signing process.
	require.Equal(t, byte(0), privKeyCopy.Serialize()[0])
}

// TestComputeUnlockingScriptNP2WKH tests that the wallet can generate a valid
// unlocking script for a nested P2WKH output.
func TestComputeUnlockingScriptNP2WKH(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet, keys, and a dummy transaction.
	w, mocks := createUnlockedWalletWithMocks(t)
	privKey, pubKey := deterministicPrivKey(t)

	// Create a NP2WKH address. This is a P2WKH output nested within a
	// P2SH output. This is done by creating the witness program first,
	// and then using its hash in a P2SH script.
	p2sh, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(btcutil.Hash160(pubKey.SerializeCompressed())).
		Script()
	require.NoError(t, err)
	addr, err := btcutil.NewAddressScriptHash(p2sh, w.cfg.ChainParams)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	// The wallet needs to be able to find the private key for the given
	// address. We mock the address store to return a mock address that,
	// when queried, will provide the private key for signing. For NP2WKH,
	// the wallet also needs the public key to reconstruct the witness
	// program, so we mock that as well.
	mocks.addrStore.On("Address",
		mock.Anything, addr,
	).Return(mocks.pubKeyAddr, nil).Twice()
	mocks.pubKeyAddr.On("AddrType").Return(
		waddrmgr.NestedWitnessPubKey).Twice()
	mocks.pubKeyAddr.On("PubKey").Return(pubKey)

	// Configure the full mock chain to return the test private key.
	//
	// NOTE: We must use a copy since the ECDH method will zero out the key.
	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())
	expectDerivedSignerPrivKey(
		t, mocks, waddrmgr.KeyScopeBIP0049Plus, waddrmgr.DerivationPath{
			InternalAccount: 0,
			Account:         0,
			Branch:          0,
			Index:           0,
		}, privKeyCopy,
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

	// Finally, we ensure that the private key was not mutated during the
	// signing process.
	require.Equal(t, byte(0), privKeyCopy.Serialize()[0])
}

// TestComputeUnlockingScriptP2TR tests that the wallet can generate a valid
// unlocking script for a P2TR key-path spend.
func TestComputeUnlockingScriptP2TR(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet, keys, and a dummy transaction.
	w, mocks := createUnlockedWalletWithMocks(t)
	privKey, pubKey := deterministicPrivKey(t)

	// Create a P2TR address for a key-path spend. This involves computing
	// the taproot output key from the internal public key.
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(
			txscript.ComputeTaprootOutputKey(pubKey, nil),
		), w.cfg.ChainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	// The wallet needs to be able to find the private key for the given
	// address. We mock the address store to return a mock address that,
	// when queried, will provide the private key for signing.
	mocks.addrStore.On("Address",
		mock.Anything, addr,
	).Return(mocks.pubKeyAddr, nil).Twice()
	mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.TaprootPubKey).Twice()

	// Configure the full mock chain to return the test private key.
	//
	// NOTE: We must use a copy since the ECDH method will zero out the key.
	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())
	expectDerivedSignerPrivKey(
		t, mocks, waddrmgr.KeyScopeBIP0086, waddrmgr.DerivationPath{
			InternalAccount: 0,
			Account:         0,
			Branch:          0,
			Index:           0,
		}, privKeyCopy,
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

	// Finally, we ensure that the private key was not mutated during the
	// signing process.
	require.Equal(t, byte(0), privKeyCopy.Serialize()[0])
}

// TestComputeUnlockingScriptFail_ScriptForOutput tests failure when
// ScriptForOutput returns an error.
func TestComputeUnlockingScriptFail_ScriptForOutput(t *testing.T) {
	t.Parallel()

	// Arrange: Set up keys, address, and transaction.
	_, pubKey := deterministicPrivKey(t)
	addr, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
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

	// Mock the address store to return an error.
	mocks.addrStore.On("Address", mock.Anything, addr).
		Return((*mockManagedAddress)(nil), errManagerNotFound).Once()

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

// TestComputeUnlockingScriptFail_PrivKey tests failure when private key
// retrieval fails.
func TestComputeUnlockingScriptFail_PrivKey(t *testing.T) {
	t.Parallel()

	// Arrange: Set up keys, address, and transaction.
	_, pubKey := deterministicPrivKey(t)
	addr, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
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
	mocks.addrStore.On("Address", mock.Anything, addr).
		Return(mocks.pubKeyAddr, nil).Twice()
	mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.PubKeyHash)

	mocks.pubKeyAddr.On("Imported").Return(false).Once()
	mocks.pubKeyAddr.On("DerivationInfo").Return(
		waddrmgr.KeyScopeBIP0044,
		waddrmgr.DerivationPath{
			InternalAccount: 0,
			Account:         0,
			Branch:          0,
			Index:           0,
		}, true,
	).Once()
	mocks.addrStore.On("FetchScopedKeyManager", waddrmgr.KeyScopeBIP0044).
		Return(mocks.accountManager, nil).Once()
	mocks.accountManager.On("DeriveFromKeyPathCache",
		waddrmgr.DerivationPath{
			InternalAccount: 0,
			Account:         0,
			Branch:          0,
			Index:           0,
		},
	).Return((*btcec.PrivateKey)(nil), errPrivKeyMock).Once()

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

// TestComputeUnlockingScriptFail_Tweak tests failure when the tweaker fails.
func TestComputeUnlockingScriptFail_Tweak(t *testing.T) {
	t.Parallel()

	// Arrange: Set up keys, address, and transaction.
	privKey, pubKey := deterministicPrivKey(t)
	addr, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
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
	mocks.addrStore.On("Address", mock.Anything, addr).
		Return(mocks.pubKeyAddr, nil).Twice()
	mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.PubKeyHash)

	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())
	expectDerivedSignerPrivKey(
		t, mocks, waddrmgr.KeyScopeBIP0044, waddrmgr.DerivationPath{
			InternalAccount: 0,
			Account:         0,
			Branch:          0,
			Index:           0,
		}, privKeyCopy,
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
	privKey, pubKey := deterministicPrivKey(t)
	addr, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
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
	mocks.addrStore.On("Address", mock.Anything, addr).
		Return(mocks.pubKeyAddr, nil).Twice()

	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())
	mocks.pubKeyAddr.On("Imported").Return(true).Once()
	mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil).Once()

	// Mock unsupported address type.
	mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.RawPubKey)

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

	privKey, pubKey := deterministicPrivKey(t)
	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())
	addr, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()),
		w.cfg.ChainParams,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	// Mock address lookup to return a valid managed address.
	mocks.addrStore.On("Address", mock.Anything, addr).
		Return(mocks.pubKeyAddr, nil).Twice()

	// Mock private key retrieval to succeed.
	mocks.pubKeyAddr.On("Imported").Return(true).Once()
	mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil).Once()

	// Mock the address type to return an unknown type (e.g. 99) that falls
	// through the switch statement in signAndAssembleScript.
	mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.AddressType(99))

	fetcher := txscript.NewCannedPrevOutputFetcher(pkScript, 10000)

	params := &UnlockingScriptParams{
		Tx:        tx,
		Output:    prevOut,
		SigHashes: txscript.NewTxSigHashes(tx, fetcher),
		HashType:  txscript.SigHashAll,
	}

	// Act: Attempt to compute the unlocking script.
	_, err = w.ComputeUnlockingScript(t.Context(), params)

	// Assert: Verify that the unsupported address type error is returned.
	require.ErrorIs(t, err, ErrUnsupportedAddressType)
}

// createDummyTestTx creates a dummy transaction for testing purposes.
func createDummyTestTx(pkScript []byte) (*wire.TxOut, *wire.MsgTx) {
	prevOut := wire.NewTxOut(100000, pkScript)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 0}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(90000, nil))

	return prevOut, tx
}

// TestComputeRawSigLegacyP2PKH tests the successful signing of a legacy P2PKH
// input.
func TestComputeRawSigLegacyP2PKH(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet, mocks, and a deterministic private key.
	w, mocks := createUnlockedWalletWithMocks(t)
	privKey, pubKey := deterministicPrivKey(t)

	// Create a P2PKH address from the public key.
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(
		pubKeyHash, w.cfg.ChainParams,
	)
	require.NoError(t, err)

	// Create a previous output and a transaction to spend it.
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	// Configure the full mock chain to return the test private key.
	//
	// NOTE: We must use a copy since the ECDH method will zero out the key.
	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())

	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}
	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return(mocks.accountManager, nil).Once()
	mocks.accountManager.On(
		"DeriveFromKeyPath", mock.Anything, mock.Anything,
	).Return(mocks.pubKeyAddr, nil).Once()
	mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil).Once()

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

	// Finally, assert that the private key is zeroed out.
	require.Equal(t, byte(0), privKeyCopy.Serialize()[0])
}

// TestComputeRawSigLegacyP2SH tests the signing of a legacy P2SH input.
func TestComputeRawSigLegacyP2SH(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet with mocks and a deterministic private
	// key for testing.
	w, mocks := createUnlockedWalletWithMocks(t)
	privKey, pubKey := deterministicPrivKey(t)
	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())

	// Create a P2SH redeem script. This involves pushing the public key
	// and the CHECKSIG opcode.
	redeemScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_DATA_33).
		AddData(pubKey.SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	// Create the P2SH address corresponding to the redeem script hash.
	addr, err := btcutil.NewAddressScriptHash(
		redeemScript, w.cfg.ChainParams,
	)
	require.NoError(t, err)

	// Create the Pay-To-Addr script (P2SH script) which will be the
	// pkScript of the previous output.
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// Create a dummy transaction and a previous output to spend.
	prevOut, tx := createDummyTestTx(pkScript)

	// Configure the address manager mock to return the correct key manager
	// and address information. P2SH addresses use BIP0049 derivation scope.
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0049Plus}
	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return(mocks.accountManager, nil).Once()
	mocks.accountManager.On("DeriveFromKeyPath",
		mock.Anything, mock.Anything).
		Return(mocks.pubKeyAddr, nil).Once()
	mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil).Once()

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

	// Arrange: Set up the wallet, mocks, and a deterministic private key.
	w, mocks := createUnlockedWalletWithMocks(t)
	privKey, pubKey := deterministicPrivKey(t)

	// Create a P2WKH address from the public key.
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(
		pubKeyHash, w.cfg.ChainParams,
	)
	require.NoError(t, err)

	// Create a previous output and a transaction to spend it.
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	// Configure the full mock chain to return the test private key.
	//
	// NOTE: We must use a copy since the ECDH method will zero out the key.
	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())

	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}
	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return(mocks.accountManager, nil).Once()
	mocks.accountManager.On(
		"DeriveFromKeyPath", mock.Anything, mock.Anything,
	).Return(mocks.pubKeyAddr, nil).Once()
	mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil).Once()

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

	// Finally, assert that the private key is zeroed out.
	require.Equal(t, byte(0), privKeyCopy.Serialize()[0])
}

// TestComputeRawSigTaprootKeySpendPath tests the successful signing of a
// Taproot P2TR input using the key-path spend.
func TestComputeRawSigTaprootKeySpendPath(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet, mocks, and a deterministic private key.
	w, mocks := createUnlockedWalletWithMocks(t)
	privKey, internalKey := deterministicPrivKey(t)

	// Create a P2TR address from the public key.
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(
			txscript.ComputeTaprootOutputKey(internalKey, nil),
		), w.cfg.ChainParams,
	)
	require.NoError(t, err)

	// Create a previous output and a transaction to spend it.
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	// Configure the full mock chain to return the test private key.
	//
	// NOTE: We must use a copy since the ECDH method will zero out the key.
	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())

	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0086}
	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return(mocks.accountManager, nil).Once()
	mocks.accountManager.On(
		"DeriveFromKeyPath", mock.Anything, mock.Anything,
	).Return(mocks.pubKeyAddr, nil).Once()
	mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil).Once()

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

	// Finally, assert that the private key is zeroed out.
	require.Equal(t, byte(0), privKeyCopy.Serialize()[0])
}

// TestComputeRawSigTaprootScriptPath tests the successful signing of a Taproot
// P2TR input using the script-path spend.
func TestComputeRawSigTaprootScriptPath(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet, mocks, and a deterministic private key.
	w, mocks := createUnlockedWalletWithMocks(t)
	privKey, internalKey := deterministicPrivKey(t)

	// Create a script to spend.
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
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey), w.cfg.ChainParams,
	)
	require.NoError(t, err)

	// Create a previous output and a transaction to spend it.
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	prevOut, tx := createDummyTestTx(pkScript)

	// Configure the full mock chain to return the test private key.
	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())

	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0086}
	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return(mocks.accountManager, nil).Once()
	mocks.accountManager.On(
		"DeriveFromKeyPath", mock.Anything, mock.Anything,
	).Return(mocks.pubKeyAddr, nil).Once()
	mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil).Once()

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

	// Finally, assert that the private key is zeroed out.
	require.Equal(t, byte(0), privKeyCopy.Serialize()[0])
}

// TestComputeRawSigFail tests various failure modes of ComputeRawSig.
func TestComputeRawSigFail(t *testing.T) {
	t.Parallel()

	privKey, _ := deterministicPrivKey(t)

	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}
	prevOut := &wire.TxOut{PkScript: []byte{0x00}}
	tx := wire.NewMsgTx(2)

	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)

	// This subtest ensures that if fetching the key manager fails during
	// the raw signature computation, the error is correctly propagated.
	t.Run("Fetch Address Fail", func(t *testing.T) {
		t.Parallel()
		w, mocks := createUnlockedWalletWithMocks(t)
		mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
			Return((*mockAccountStore)(nil),
				errManagerNotFound).Once()

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

	// This subtest ensures that if obtaining the private key from the
	// managed address fails during raw signature computation, the error is
	// correctly propagated.
	t.Run("PrivKey Fail", func(t *testing.T) {
		t.Parallel()
		w, mocks := createUnlockedWalletWithMocks(t)
		mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
			Return(mocks.accountManager, nil).Once()

		mocks.accountManager.On("DeriveFromKeyPath",
			mock.Anything, mock.Anything).
			Return(mocks.pubKeyAddr, nil).Once()

		mocks.pubKeyAddr.On("PrivKey").Return((*btcec.PrivateKey)(nil),
			errPrivKeyMock).Once()

		params := &RawSigParams{
			Tx:        tx,
			Output:    prevOut,
			SigHashes: sigHashes,
			HashType:  txscript.SigHashAll,
			Path:      path,
			Details:   LegacySpendDetails{},
		}

		_, err := w.ComputeRawSig(t.Context(), params)
		require.ErrorContains(t, err, "privkey error")
	})

	// This subtest verifies that if the private key tweaking function
	// returns an error, the raw signature computation correctly propagates
	// that error.
	t.Run("Tweak Fail", func(t *testing.T) {
		t.Parallel()
		w, mocks := createUnlockedWalletWithMocks(t)
		mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
			Return(mocks.accountManager, nil).Once()

		mocks.accountManager.On("DeriveFromKeyPath",
			mock.Anything, mock.Anything).
			Return(mocks.pubKeyAddr, nil).Once()

		privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())
		mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil).Once()

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
		mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
			Return(mocks.accountManager, nil).Once()

		mocks.accountManager.On("DeriveFromKeyPath",
			mock.Anything, mock.Anything).
			Return(mocks.pubKeyAddr, nil).Once()

		privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())
		mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil).Once()

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

		mockDetails.On("Sign", params, privKeyCopy).
			Return((RawSignature)(nil),
				errSignMock)
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

		path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0086}
		mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
			Return(mocks.accountManager, nil).Once()

		mocks.accountManager.On("DeriveFromKeyPath",
			mock.Anything, mock.Anything).
			Return(mocks.pubKeyAddr, nil).Once()

		privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())
		mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil).Once()

		params := &RawSigParams{
			Tx:   wire.NewMsgTx(2),
			Path: path,
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
		mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
			Return(mocks.accountManager, nil).Once()
		mocks.accountManager.On("DeriveFromKeyPath",
			mock.Anything, mock.Anything).
			Return(mocks.pubKeyAddr, nil).Once()

		privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())
		mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil).Once()

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
		mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
			Return(mocks.accountManager, nil).Once()
		mocks.accountManager.On("DeriveFromKeyPath",
			mock.Anything, mock.Anything).
			Return(mocks.pubKeyAddr, nil).Once()

		privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())
		mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil).Once()

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
		mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
			Return(mocks.accountManager, nil).Once()
		mocks.accountManager.On("DeriveFromKeyPath",
			mock.Anything, mock.Anything).
			Return(mocks.pubKeyAddr, nil).Once()

		privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())
		mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil).Once()

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

	// Arrange: Set up the wallet with mocks, a test key, and a
	// derivation path.
	w, mocks := createUnlockedWalletWithMocks(t)
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	path := BIP32Path{
		KeyScope: waddrmgr.KeyScopeBIP0084,
		DerivationPath: waddrmgr.DerivationPath{
			InternalAccount: 0,
			Branch:          0,
			Index:           0,
		},
	}

	// Set up the mock account manager and the mock address that will be
	// returned by the derivation call.
	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())

	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return(mocks.accountManager, nil).Once()
	mocks.accountManager.On(
		"DeriveFromKeyPath", mock.Anything, path.DerivationPath,
	).Return(mocks.pubKeyAddr, nil).Once()
	mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil).Once()

	// Act: Derive the private key.
	derivedKey, err := w.DerivePrivKey(t.Context(), path)

	// Assert: Check that the correct key is returned without error.
	require.NoError(t, err)
	require.Equal(t, privKey.Serialize(), derivedKey.Serialize())
}

// TestDerivePrivKeyFails tests the failure case where the key derivation fails.
func TestDerivePrivKeyFails(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and a test path. Configure the mock
	// addrStore to return an error when fetching the key manager.
	w, mocks := createUnlockedWalletWithMocks(t)
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}

	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return((*mockAccountStore)(nil), errManagerNotFound).Once()

	// Act: Attempt to derive the private key.
	_, err := w.DerivePrivKey(t.Context(), path)

	// Assert: Check that the error is propagated correctly.
	require.ErrorIs(t, err, errManagerNotFound)
}

// TestGetPrivKeyForAddressSuccess tests the successful retrieval of a private
// key by address.
func TestGetPrivKeyForAddressSuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet, mocks, and a deterministic private key.
	w, mocks := createUnlockedWalletWithMocks(t)
	privKey, pubKey := deterministicPrivKey(t)

	// Create a P2PKH address from the public key.
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(
		pubKeyHash, w.cfg.ChainParams,
	)
	require.NoError(t, err)

	// Configure the mock chain to return the test private key.
	//
	// NOTE: We must use a copy since the method will zero out the key.
	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())

	mocks.addrStore.On("Address", mock.Anything, addr).
		Return(mocks.pubKeyAddr, nil).Once()
	mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil).Once()

	// Act: Get the private key for the address.
	retrievedKey, err := w.GetPrivKeyForAddress(t.Context(), addr)

	// Assert: Check that the correct key is returned.
	require.NoError(t, err)
	require.Equal(t, privKey.Serialize(), retrievedKey.Serialize())
}

// TestGetPrivKeyForAddressFail tests the failure cases for retrieval of a
// private key by address.
func TestGetPrivKeyForAddressFail(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet and mocks.
	w, mocks := createUnlockedWalletWithMocks(t)
	addr, err := btcutil.NewAddressPubKeyHash(
		make([]byte, 20), w.cfg.ChainParams,
	)
	require.NoError(t, err)

	// Case 1: Address lookup fails.
	mocks.addrStore.On("Address", mock.Anything, addr).
		Return((*mockManagedAddress)(nil), errManagerNotFound).Once()

	_, err = w.GetPrivKeyForAddress(t.Context(), addr)
	require.ErrorIs(t, err, errManagerNotFound)

	// Case 2: Address is not a pubkey address.
	// We need a separate mock for this to ensure clean separation.
	//
	// NOTE: We can reuse the existing mocks but need to reset expectations
	// or ensure ordering. Since we are in a single test function, we can
	// just sequence them.
	mockScriptAddr := &mockManagedAddress{}
	mocks.addrStore.On("Address", mock.Anything, addr).
		Return(mockScriptAddr, nil).Once()

	_, err = w.GetPrivKeyForAddress(t.Context(), addr)
	require.ErrorIs(t, err, ErrNoAssocPrivateKey)
}

// TestDerivePrivKeyFail tests failure modes of DerivePrivKey.
func TestDerivePrivKeyFail(t *testing.T) {
	t.Parallel()

	w, mocks := createUnlockedWalletWithMocks(t)
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}

	// Test Case 1: Fetching key manager fails.
	//
	// We mock the address store to return an error when fetching the key
	// manager. We expect this error to be propagated.
	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return((*mockAccountStore)(nil), errManagerNotFound).Once()

	_, err := w.DerivePrivKey(t.Context(), path)
	require.ErrorIs(t, err, errManagerNotFound)

	// Test Case 2: PrivKey retrieval fails.
	//
	// We mock the key manager to return a valid address, but mock the
	// address to return an error when fetching the private key. We expect
	// a wrapped error indicating the failure.
	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return(mocks.accountManager, nil).Once()
	mocks.accountManager.On(
		"DeriveFromKeyPath", mock.Anything, mock.Anything,
	).Return(mocks.pubKeyAddr, nil).Once()
	mocks.pubKeyAddr.On("PrivKey").
		Return((*btcec.PrivateKey)(nil), errPrivKeyMock).Once()

	_, err = w.DerivePrivKey(t.Context(), path)
	require.ErrorContains(t, err, "cannot get private key")
}

// TestECDHFail tests failure modes of ECDH.
func TestECDHFail(t *testing.T) {
	t.Parallel()

	w, mocks := createUnlockedWalletWithMocks(t)
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}
	privKey, _ := btcec.NewPrivateKey()

	// Test Case 1: Fetching key manager fails.
	//
	// We mock the address store to return an error when fetching the key
	// manager. We expect this error to be propagated.
	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return((*mockAccountStore)(nil), errManagerNotFound).Once()

	_, err := w.ECDH(t.Context(), path, privKey.PubKey())
	require.ErrorIs(t, err, errManagerNotFound)

	// Test Case 2: PrivKey retrieval fails.
	//
	// We mock the key manager to return a valid address, but mock the
	// address to return an error when fetching the private key. We expect
	// a wrapped error indicating the failure.
	mocks.addrStore.On("FetchScopedKeyManager", path.KeyScope).
		Return(mocks.accountManager, nil).Once()
	mocks.accountManager.On(
		"DeriveFromKeyPath", mock.Anything, mock.Anything,
	).Return(mocks.pubKeyAddr, nil).Once()
	mocks.pubKeyAddr.On("PrivKey").
		Return((*btcec.PrivateKey)(nil), errPrivKeyMock).Once()

	_, err = w.ECDH(t.Context(), path, privKey.PubKey())
	require.ErrorContains(t, err, "cannot get private key")
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
