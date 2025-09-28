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

// TestComputeUnlockingScriptP2PKH tests that the wallet can generate a valid
// unlocking script for a P2PKH output.
func TestComputeUnlockingScriptP2PKH(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet, keys, and a dummy transaction that will
	// be used to spend the P2PKH output.
	w, mocks := testWalletWithMocks(t)
	privKey, pubKey := deterministicPrivKey(t)

	// Create a P2PKH address and the corresponding previous output script.
	// This is the output we want to create an unlocking script for.
	addr, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), w.chainParams,
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
	).Return(mocks.pubKeyAddr, nil)
	mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.PubKeyHash).Twice()

	// Configure the full mock chain to return the test private key.
	//
	// NOTE: We must use a copy since the ECDH method will zero out the key.
	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())
	mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil)

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
	w, mocks := testWalletWithMocks(t)
	privKey, pubKey := deterministicPrivKey(t)

	// Create a P2WKH address and the corresponding previous output script.
	addr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), w.chainParams,
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
	).Return(mocks.pubKeyAddr, nil)
	mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey).Twice()

	// Configure the full mock chain to return the test private key.
	//
	// NOTE: We must use a copy since the ECDH method will zero out the key.
	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())
	mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil)

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
	w, mocks := testWalletWithMocks(t)
	privKey, pubKey := deterministicPrivKey(t)

	// Create a NP2WKH address. This is a P2WKH output nested within a
	// P2SH output. This is done by creating the witness program first,
	// and then using its hash in a P2SH script.
	p2sh, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(btcutil.Hash160(pubKey.SerializeCompressed())).
		Script()
	require.NoError(t, err)
	addr, err := btcutil.NewAddressScriptHash(p2sh, w.chainParams)
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
	).Return(mocks.pubKeyAddr, nil)
	mocks.pubKeyAddr.On("AddrType").Return(
		waddrmgr.NestedWitnessPubKey).Twice()
	mocks.pubKeyAddr.On("PubKey").Return(pubKey)

	// Configure the full mock chain to return the test private key.
	//
	// NOTE: We must use a copy since the ECDH method will zero out the key.
	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())
	mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil)

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
	w, mocks := testWalletWithMocks(t)
	privKey, pubKey := deterministicPrivKey(t)

	// Create a P2TR address for a key-path spend. This involves computing
	// the taproot output key from the internal public key.
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(
			txscript.ComputeTaprootOutputKey(pubKey, nil),
		), w.chainParams,
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
	).Return(mocks.pubKeyAddr, nil)
	mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.TaprootPubKey).Twice()

	// Configure the full mock chain to return the test private key.
	//
	// NOTE: We must use a copy since the ECDH method will zero out the key.
	privKeyCopy, _ := btcec.PrivKeyFromBytes(privKey.Serialize())
	mocks.pubKeyAddr.On("PrivKey").Return(privKeyCopy, nil)

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

// createDummyTestTx creates a dummy transaction for testing purposes.
func createDummyTestTx(pkScript []byte) (*wire.TxOut, *wire.MsgTx) {
	prevOut := wire.NewTxOut(100000, pkScript)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 0}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(90000, nil))

	return prevOut, tx
}

// TestComputeRawSigLegacy tests the successful signing of a legacy P2PKH
// input.
func TestComputeRawSigLegacy(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet, mocks, and a deterministic private key.
	w, mocks := testWalletWithMocks(t)
	privKey, pubKey := deterministicPrivKey(t)

	// Create a P2PKH address from the public key.
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(
		pubKeyHash, w.chainParams,
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

// TestComputeRawSigSegwitV0 tests the successful signing of a SegWit v0 P2WKH
// input.
func TestComputeRawSigSegwitV0(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet, mocks, and a deterministic private key.
	w, mocks := testWalletWithMocks(t)
	privKey, pubKey := deterministicPrivKey(t)

	// Create a P2WKH address from the public key.
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(
		pubKeyHash, w.chainParams,
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

// TestComputeRawSigTaproot tests the successful signing of a Taproot P2TR
// input using the key-path spend.
func TestComputeRawSigTaproot(t *testing.T) {
	t.Parallel()

	// Arrange: Set up the wallet, mocks, and a deterministic private key.
	w, mocks := testWalletWithMocks(t)
	privKey, internalKey := deterministicPrivKey(t)

	// Create a P2TR address from the public key.
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(
			txscript.ComputeTaprootOutputKey(internalKey, nil),
		), w.chainParams,
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
