// Copyright (c) 2020 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
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
