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
)

// TestComputeInputScript checks that the wallet can create the full
// witness script for a witness output.
func TestComputeInputScript(t *testing.T) {
	t.Parallel()

	w := testWallet(t)

	testCases := []struct {
		name              string
		scope             waddrmgr.KeyScope
		expectedScriptLen int
	}{{
		name:              "BIP084 P2WKH",
		scope:             waddrmgr.KeyScopeBIP0084,
		expectedScriptLen: 0,
	}, {
		name:              "BIP049 nested P2WKH",
		scope:             waddrmgr.KeyScopeBIP0049Plus,
		expectedScriptLen: 23,
	}}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			runTestCase(t, w, tc.scope, tc.expectedScriptLen)
		})
	}
}

func runTestCase(t *testing.T, w *Wallet, scope waddrmgr.KeyScope,
	scriptLen int) {

	// Create an address we can use to send some coins to.
	addr, err := w.CurrentAddress(0, scope)
	if err != nil {
		t.Fatalf("unable to get current address: %v", addr)
	}
	p2shAddr, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("unable to convert wallet address to p2sh: %v", err)
	}

	// Add an output paying to the wallet's address to the database.
	utxOut := wire.NewTxOut(100000, p2shAddr)
	incomingTx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{utxOut},
	}
	addUtxo(t, w, incomingTx)

	// Create a transaction that spends the UTXO created above and spends to
	// the same address again.
	prevOut := wire.OutPoint{
		Hash:  incomingTx.TxHash(),
		Index: 0,
	}
	outgoingTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: prevOut,
		}},
		TxOut: []*wire.TxOut{utxOut},
	}
	fetcher := txscript.NewCannedPrevOutputFetcher(
		utxOut.PkScript, utxOut.Value,
	)
	sigHashes := txscript.NewTxSigHashes(outgoingTx, fetcher)

	// Compute the input script to spend the UTXO now.
	witness, script, err := w.ComputeInputScript(
		outgoingTx, utxOut, 0, sigHashes, txscript.SigHashAll, nil,
	)
	if err != nil {
		t.Fatalf("error computing input script: %v", err)
	}
	if len(script) != scriptLen {
		t.Fatalf("unexpected script length, got %d wanted %d",
			len(script), scriptLen)
	}
	if len(witness) != 2 {
		t.Fatalf("unexpected witness stack length, got %d, wanted %d",
			len(witness), 2)
	}

	// Finally verify that the created witness is valid.
	outgoingTx.TxIn[0].Witness = witness
	outgoingTx.TxIn[0].SignatureScript = script
	err = validateMsgTx(
		outgoingTx, [][]byte{utxOut.PkScript}, []btcutil.Amount{100000},
	)
	if err != nil {
		t.Fatalf("error validating tx: %v", err)
	}
}

// TestDerivePubKeySuccess tests the successful derivation of a public key.
func TestDerivePubKeySuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet with mocks, a test key, and a
	// derivation path.
	w, mocks := testWalletWithMocks(t)
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
	w, mocks := testWalletWithMocks(t)
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
	w, mocks := testWalletWithMocks(t)
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
	w, mocks := testWalletWithMocks(t)
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}

	// We need a valid address for the error message.
	addr, err := btcutil.NewAddressWitnessPubKeyHash(
		make([]byte, 20), w.chainParams,
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
	w, mocks := testWalletWithMocks(t)

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
	w, mocks := testWalletWithMocks(t)
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

// TestSignMessage tests the signing of a message with different signature
// types.
func TestSignMessage(t *testing.T) {
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

	testCases := []struct {
		// name is the name of the test case.
		name string

		// intent is the signing intent to use for the test.
		intent *SignMessageIntent

		// verify is a function that verifies the signature produced by
		// the signing intent.
		verify func(t *testing.T, sig Signature,
			pubKey *btcec.PublicKey)
	}{
		{
			name: "ECDSA success",
			intent: &SignMessageIntent{
				Msg:        msg,
				DoubleHash: false,
				CompactSig: false,
			},
			verify: func(t *testing.T, sig Signature,
				pubKey *btcec.PublicKey) {

				t.Helper()

				ecdsaSig, ok := sig.(ECDSASignature)
				require.True(t, ok, "expected ECDSASignature")
				msgHash := btcutil.Hash160(msg)
				require.True(
					t, ecdsaSig.Verify(msgHash, pubKey),
					"signature invalid",
				)
			},
		},
		{
			name: "ECDSA compact success",
			intent: &SignMessageIntent{
				Msg:        msg,
				DoubleHash: true,
				CompactSig: true,
			},
			verify: func(t *testing.T, sig Signature,
				pubKey *btcec.PublicKey) {

				t.Helper()

				compactSig, ok := sig.(CompactSignature)
				require.True(t, ok, "expected CompactSignature")
				msgHash := chainhash.DoubleHashB(msg)
				recoveredKey, _, err := ecdsa.RecoverCompact(
					compactSig, msgHash,
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
			intent: &SignMessageIntent{
				Msg: msg,
				Schnorr: &SchnorrSignOpts{
					Tag: []byte("test tag"),
				},
			},
			verify: func(t *testing.T, sig Signature,
				pubKey *btcec.PublicKey) {

				t.Helper()

				schnorrSig, ok := sig.(SchnorrSignature)
				require.True(t, ok, "expected SchnorrSignature")

				msgHash := chainhash.TaggedHash(
					[]byte("test tag"), msg,
				)
				require.True(t,
					schnorrSig.Verify(msgHash[:], pubKey),
					"signature invalid",
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
			w, mocks := testWalletWithMocks(t)

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
			sig, err := w.SignMessage(t.Context(), path, tc.intent)

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
