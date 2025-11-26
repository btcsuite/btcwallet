// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/pkg/btcunit"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	errDb           = errors.New("db error")
	errKeyNotFound  = errors.New("key not found")
	errAddrNotFound = errors.New("addr not found")
)

// TestFindCredit tests that the findCredit helper returns true if a credit
// exists at the specified index, and false otherwise.
func TestFindCredit(t *testing.T) {
	t.Parallel()

	// Arrange: Create TxDetails with credits at indices 0 and 2.
	txDetails := &wtxmgr.TxDetails{
		Credits: []wtxmgr.CreditRecord{
			{Index: 0},
			{Index: 2},
		},
	}

	// Arrange: Define test cases to check for credits at various indices.
	testCases := []struct {
		name          string
		index         uint32
		expectedFound bool
	}{
		{
			name:          "credit exists at index 0",
			index:         0,
			expectedFound: true,
		},
		{
			name:          "credit exists at index 2",
			index:         2,
			expectedFound: true,
		},
		{
			name:          "credit does not exist at index 1",
			index:         1,
			expectedFound: false,
		},
		{
			name:          "credit does not exist at index 3",
			index:         3,
			expectedFound: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act: Call findCredit with the configured TxDetails
			// and index.
			found := findCredit(txDetails, tc.index)

			// Assert: Verify that the returned boolean matches the
			// expected outcome.
			require.Equal(t, tc.expectedFound, found)
		})
	}
}

// TestFetchAndValidateUtxoSuccess tests that fetchAndValidateUtxo correctly
// retrieves transaction details and validates ownership.
func TestFetchAndValidateUtxoSuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Create a transaction input (txHash:0) and mock the wallet's
	// transaction store to return a corresponding credit at index 0.
	txHash := chainhash.Hash{1}
	txIn := &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: txHash, Index: 0},
	}

	txDetails := &wtxmgr.TxDetails{
		TxRecord: wtxmgr.TxRecord{
			MsgTx: wire.MsgTx{
				TxOut: []*wire.TxOut{
					{Value: 1000},
				},
			},
		},
		Credits: []wtxmgr.CreditRecord{
			{Index: 0},
		},
	}

	w, mocks := testWalletWithMocks(t)

	// Mock the transaction store to return the details for our txHash.
	mocks.txStore.On(
		"TxDetails", mock.Anything,
		mock.MatchedBy(func(h *chainhash.Hash) bool {
			return h.IsEqual(&txHash)
		}),
	).Return(txDetails, nil)

	// Act: Call fetchAndValidateUtxo with the valid input.
	tx, utxo, err := w.fetchAndValidateUtxo(txIn)

	// Assert: Verify that no error occurred and that the returned
	// transaction and UTXO match the expected values from the store.
	require.NoError(t, err)
	require.NotNil(t, tx)
	require.NotNil(t, utxo)
	require.Equal(t, txDetails.MsgTx.TxOut[0], utxo)
}

// TestFetchAndValidateUtxoError tests that fetchAndValidateUtxo returns the
// expected errors for various failure conditions.
func TestFetchAndValidateUtxoError(t *testing.T) {
	t.Parallel()

	// Arrange: Prepare common data structures for the test cases.
	txHash := chainhash.Hash{1}

	// txIn pointing to an unlocked outpoint (Index 0).
	txIn := &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: txHash, Index: 0},
	}

	// txInLocked pointing to a locked outpoint (Index 1).
	txInLocked := &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: txHash, Index: 1},
	}

	// txDetails contains credits for both Index 0 and Index 1.
	// Index 0 is used for unlocked tests.
	// Index 1 is used for the locked test.
	txDetails := &wtxmgr.TxDetails{
		TxRecord: wtxmgr.TxRecord{
			MsgTx: wire.MsgTx{
				TxOut: []*wire.TxOut{
					{Value: 1000},
					{Value: 1000},
				},
			},
		},
		Credits: []wtxmgr.CreditRecord{
			{Index: 0},
			{Index: 1},
		},
	}

	noCreditDetails := &wtxmgr.TxDetails{
		TxRecord: txDetails.TxRecord,
		Credits:  []wtxmgr.CreditRecord{},
	}

	testCases := []struct {
		name          string
		txIn          *wire.TxIn
		mockTxDetails *wtxmgr.TxDetails
		mockErr       error
		expectedErr   error
	}{
		{
			name:          "tx not found",
			txIn:          txIn,
			mockTxDetails: nil,
			mockErr:       ErrTxNotFound,
			expectedErr:   ErrNotMine,
		},
		{
			name:          "store error",
			txIn:          txIn,
			mockTxDetails: nil,
			mockErr:       errDb,
			expectedErr:   errDb,
		},
		{
			name:          "not credit",
			txIn:          txIn,
			mockTxDetails: noCreditDetails,
			mockErr:       nil,
			expectedErr:   ErrNotMine,
		},
		{
			name:          "utxo locked",
			txIn:          txInLocked,
			mockTxDetails: txDetails,
			mockErr:       nil,
			expectedErr:   ErrUtxoLocked,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w, mocks := testWalletWithMocks(t)

			// Arrange: Lock the "locked" outpoint to simulate a
			// locked UTXO scenario.
			w.LockOutpoint(txInLocked.PreviousOutPoint)

			// Arrange: Mock the transaction store to return the
			// configured details or error for the specific test
			// case.
			mocks.txStore.On(
				"TxDetails", mock.Anything,
				mock.MatchedBy(func(h *chainhash.Hash) bool {
					return h.IsEqual(&txHash)
				}),
			).Return(tc.mockTxDetails, tc.mockErr)

			// Act: Call fetchAndValidateUtxo with the configured
			// input.
			tx, utxo, err := w.fetchAndValidateUtxo(tc.txIn)

			// Assert: Verify that the returned error matches the
			// expected error and that no transaction or UTXO is
			// returned.
			require.ErrorIs(t, err, tc.expectedErr)
			require.Nil(t, tx)
			require.Nil(t, utxo)
		})
	}
}

// TestDecorateInputSegWitV0 tests that decorateInput correctly populates
// PSBT input fields for a SegWit v0 (P2WKH) input.
func TestDecorateInputSegWitV0(t *testing.T) {
	t.Parallel()

	// Arrange: Setup private and public keys for a P2WKH address.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	// Arrange: Create a P2WKH address and its corresponding script.
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)

	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	// Arrange: Define key scope and derivation path for address manager
	// mocks.
	keyScope := waddrmgr.KeyScopeBIP0084
	derivationPath := waddrmgr.DerivationPath{
		Account: 0,
		Branch:  0,
		Index:   0,
	}

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock the address manager to return our P2WKH address as a
	// ManagedPubKeyAddress when `Address` is called with the P2WKH
	// address.
	mocks.addrStore.On(
		"Address", mock.Anything,
		mock.MatchedBy(func(addr btcutil.Address) bool {
			return addr.String() == p2wkhAddr.String()
		}),
	).Return(mocks.pubKeyAddr, nil)

	// Arrange: Mock the ManagedPubKeyAddress methods to return relevant
	// derivation and public key information.
	mocks.pubKeyAddr.On("Imported").Return(false)
	mocks.pubKeyAddr.On("DerivationInfo").Return(
		keyScope, derivationPath, true,
	)
	mocks.pubKeyAddr.On("PubKey").Return(pubKey)
	mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey)

	// Arrange: Create a UTXO with the P2WKH script and an empty PSBT input.
	utxo := &wire.TxOut{
		Value:    1000,
		PkScript: p2wkhScript,
	}
	tx := &wire.MsgTx{}
	pInput := &psbt.PInput{}

	// Act: Call decorateInput to populate the PSBT input.
	err = w.decorateInput(t.Context(), pInput, tx, utxo)

	// Assert: Verify no error occurred and that the PSBT input is correctly
	// populated with WitnessUtxo, NonWitnessUtxo, SighashType, and BIP32
	// derivation info.
	require.NoError(t, err)
	require.Equal(t, utxo, pInput.WitnessUtxo)
	require.Equal(t, tx, pInput.NonWitnessUtxo)
	require.Equal(t, txscript.SigHashAll, pInput.SighashType)
	require.Len(t, pInput.Bip32Derivation, 1)
	require.Equal(
		t, pubKey.SerializeCompressed(),
		pInput.Bip32Derivation[0].PubKey,
	)
}

// TestDecorateInputTaproot tests that decorateInput correctly populates
// PSBT input fields for a Taproot (SegWit v1) input.
func TestDecorateInputTaproot(t *testing.T) {
	t.Parallel()

	// Arrange: Setup private and public keys for a Taproot address.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	// Arrange: Create a Taproot address and its corresponding script.
	taprootAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(pubKey), &chainParams,
	)
	require.NoError(t, err)

	taprootScript, err := txscript.PayToAddrScript(taprootAddr)
	require.NoError(t, err)

	// Arrange: Define key scope and derivation path for address manager
	// mocks.
	keyScope := waddrmgr.KeyScopeBIP0084
	derivationPath := waddrmgr.DerivationPath{
		Account: 0,
		Branch:  0,
		Index:   0,
	}

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock the address manager to return our Taproot address as a
	// ManagedPubKeyAddress when `Address` is called with the Taproot
	// address.
	mocks.addrStore.On(
		"Address", mock.Anything,
		mock.MatchedBy(func(addr btcutil.Address) bool {
			return addr.String() == taprootAddr.String()
		}),
	).Return(mocks.pubKeyAddr, nil)

	// Arrange: Mock the ManagedPubKeyAddress methods to return relevant
	// derivation and public key information. AddrType is not strictly
	// checked for Taproot inputs in decorateInput, so no mock is needed
	// for it.
	mocks.pubKeyAddr.On("Imported").Return(false)
	mocks.pubKeyAddr.On("DerivationInfo").Return(
		keyScope, derivationPath, true,
	)
	mocks.pubKeyAddr.On("PubKey").Return(pubKey)

	// Arrange: Create a UTXO with the Taproot script and an empty PSBT
	// input.
	utxo := &wire.TxOut{
		Value:    1000,
		PkScript: taprootScript,
	}
	tx := &wire.MsgTx{}
	pInput := &psbt.PInput{}

	// Act: Call decorateInput to populate the PSBT input.
	err = w.decorateInput(t.Context(), pInput, tx, utxo)

	// Assert: Verify no error occurred and that the PSBT input is
	// correctly populated with WitnessUtxo, SighashType, and Taproot BIP32
	// derivation info, including the x-only public key.
	require.NoError(t, err)
	require.Equal(t, utxo, pInput.WitnessUtxo)
	require.Equal(t, txscript.SigHashDefault, pInput.SighashType)
	require.Len(t, pInput.TaprootBip32Derivation, 1)
	require.Equal(
		t, schnorr.SerializePubKey(pubKey),
		pInput.TaprootBip32Derivation[0].XOnlyPubKey,
	)
}

// TestDecorateInputErrExtractAddr tests that decorateInput returns
// ErrUnableToExtractAddress when the pkScript does not contain a valid
// address.
func TestDecorateInputErrExtractAddr(t *testing.T) {
	t.Parallel()

	w, _ := testWalletWithMocks(t)

	// Arrange: Create a UTXO with an OP_RETURN script, which cannot be
	// parsed into a valid address.
	utxo := &wire.TxOut{
		Value:    1000,
		PkScript: []byte{0x6a}, // OP_RETURN
	}
	tx := &wire.MsgTx{}
	pInput := &psbt.PInput{}

	// Act: Call decorateInput.
	err := w.decorateInput(t.Context(), pInput, tx, utxo)

	// Assert: Verify the error.
	require.ErrorIs(t, err, ErrUnableToExtractAddress)
}

// TestDecorateInputErrAddrInfo tests that decorateInput returns an error when
// the address lookup fails.
func TestDecorateInputErrAddrInfo(t *testing.T) {
	t.Parallel()

	// Arrange: Setup keys and address.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)

	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock AddressInfo to return an error.
	mocks.addrStore.On(
		"Address", mock.Anything, mock.Anything,
	).Return(nil, errDb)

	utxo := &wire.TxOut{
		Value:    1000,
		PkScript: p2wkhScript,
	}
	tx := &wire.MsgTx{}
	pInput := &psbt.PInput{}

	// Act: Call decorateInput.
	err = w.decorateInput(t.Context(), pInput, tx, utxo)

	// Assert: Verify the error.
	require.ErrorIs(t, err, errDb)
}

// TestDecorateInputErrNotPubKey tests that decorateInput returns
// ErrNotPubKeyAddress when the address is not a ManagedPubKeyAddress.
func TestDecorateInputErrNotPubKey(t *testing.T) {
	t.Parallel()

	// Arrange: Setup keys and address.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)

	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock AddressInfo to return a generic ManagedAddress
	// (mocks.addr) instead of a ManagedPubKeyAddress (mocks.pubKeyAddr).
	mocks.addrStore.On(
		"Address", mock.Anything, mock.Anything,
	).Return(mocks.addr, nil)

	mocks.addr.On("Address").Return(p2wkhAddr)

	utxo := &wire.TxOut{
		Value:    1000,
		PkScript: p2wkhScript,
	}
	tx := &wire.MsgTx{}
	pInput := &psbt.PInput{}

	// Act: Call decorateInput.
	err = w.decorateInput(t.Context(), pInput, tx, utxo)

	// Assert: Verify the error.
	require.ErrorIs(t, err, ErrNotPubKeyAddress)
}

// TestDecorateInputErrImported tests that decorateInput returns
// ErrDerivationPathNotFound when the address is imported.
func TestDecorateInputErrImported(t *testing.T) {
	t.Parallel()

	// Arrange: Setup keys and address.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)

	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock AddressInfo to return a ManagedPubKeyAddress that is
	// marked as imported.
	mocks.addrStore.On(
		"Address", mock.Anything, mock.Anything,
	).Return(mocks.pubKeyAddr, nil)

	mocks.pubKeyAddr.On("Imported").Return(true)
	mocks.pubKeyAddr.On("Address").Return(p2wkhAddr)

	utxo := &wire.TxOut{
		Value:    1000,
		PkScript: p2wkhScript,
	}
	tx := &wire.MsgTx{}
	pInput := &psbt.PInput{}

	// Act: Call decorateInput.
	err = w.decorateInput(t.Context(), pInput, tx, utxo)

	// Assert: Verify the error.
	require.ErrorIs(t, err, ErrDerivationPathNotFound)
}

// TestDecorateInputErrDerivationMissing tests that decorateInput returns
// ErrDerivationPathNotFound when derivation info is missing.
func TestDecorateInputErrDerivationMissing(t *testing.T) {
	t.Parallel()

	// Arrange: Setup keys and address.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)

	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock AddressInfo to return a ManagedPubKeyAddress that has
	// no derivation info.
	mocks.addrStore.On(
		"Address", mock.Anything, mock.Anything,
	).Return(mocks.pubKeyAddr, nil)

	mocks.pubKeyAddr.On("Imported").Return(false)
	mocks.pubKeyAddr.On("DerivationInfo").Return(
		waddrmgr.KeyScope{}, waddrmgr.DerivationPath{}, false,
	)
	mocks.pubKeyAddr.On("Address").Return(p2wkhAddr)

	utxo := &wire.TxOut{
		Value:    1000,
		PkScript: p2wkhScript,
	}
	tx := &wire.MsgTx{}
	pInput := &psbt.PInput{}

	// Act: Call decorateInput.
	err = w.decorateInput(t.Context(), pInput, tx, utxo)

	// Assert: Verify the error.
	require.ErrorIs(t, err, ErrDerivationPathNotFound)
}

// TestDecorateInputsSuccess tests that DecorateInputs correctly decorates
// known inputs and skips unknown inputs when skipUnknown is true.
func TestDecorateInputsSuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Setup keys and address.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)
	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	// Arrange: Define 3 inputs.
	// Input 0: Known (TxHash0)
	// Input 1: Unknown (TxHash1)
	// Input 2: Known (TxHash2)
	txHash0 := chainhash.Hash{0}
	txHash1 := chainhash.Hash{1}
	txHash2 := chainhash.Hash{2}

	unsignedTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{
				Hash: txHash0, Index: 0,
			}},
			{PreviousOutPoint: wire.OutPoint{
				Hash: txHash1, Index: 0,
			}},
			{PreviousOutPoint: wire.OutPoint{
				Hash: txHash2, Index: 0,
			}},
		},
	}

	packet, err := psbt.NewFromUnsignedTx(unsignedTx)
	require.NoError(t, err)

	// Arrange: Setup TxDetails for known inputs.
	txDetails0 := &wtxmgr.TxDetails{
		TxRecord: wtxmgr.TxRecord{
			MsgTx: wire.MsgTx{
				TxOut: []*wire.TxOut{{
					Value: 1000, PkScript: p2wkhScript,
				}},
			},
		},
		Credits: []wtxmgr.CreditRecord{{Index: 0}},
	}
	txDetails2 := &wtxmgr.TxDetails{
		TxRecord: wtxmgr.TxRecord{
			MsgTx: wire.MsgTx{
				TxOut: []*wire.TxOut{{
					Value: 2000, PkScript: p2wkhScript,
				}},
			},
		},
		Credits: []wtxmgr.CreditRecord{{Index: 0}},
	}

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock TxDetails lookups.
	// Input 0 -> Found
	mocks.txStore.On(
		"TxDetails", mock.Anything,
		mock.MatchedBy(func(h *chainhash.Hash) bool {
			return h.IsEqual(&txHash0)
		}),
	).Return(txDetails0, nil)

	// Input 1 -> Not Found
	mocks.txStore.On(
		"TxDetails", mock.Anything,
		mock.MatchedBy(func(h *chainhash.Hash) bool {
			return h.IsEqual(&txHash1)
		}),
	).Return(nil, ErrTxNotFound)

	// Input 2 -> Found
	mocks.txStore.On(
		"TxDetails", mock.Anything,
		mock.MatchedBy(func(h *chainhash.Hash) bool {
			return h.IsEqual(&txHash2)
		}),
	).Return(txDetails2, nil)

	// Arrange: Mock Address lookup (common for both known inputs).
	mocks.addrStore.On(
		"Address", mock.Anything,
		mock.MatchedBy(func(addr btcutil.Address) bool {
			return addr.String() == p2wkhAddr.String()
		}),
	).Return(mocks.pubKeyAddr, nil)

	// Arrange: Mock ManagedPubKeyAddress methods.
	mocks.pubKeyAddr.On("Imported").Return(false)
	mocks.pubKeyAddr.On("DerivationInfo").Return(
		waddrmgr.KeyScopeBIP0084, waddrmgr.DerivationPath{}, true,
	)
	mocks.pubKeyAddr.On("PubKey").Return(pubKey)
	mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey)

	// Act: Call DecorateInputs with skipUnknown=true.
	_, err = w.DecorateInputs(t.Context(), packet, true)
	require.NoError(t, err)

	// Assert: Input 0 is decorated.
	require.NotNil(t, packet.Inputs[0].WitnessUtxo)
	require.Equal(t, int64(1000), packet.Inputs[0].WitnessUtxo.Value)
	require.Len(t, packet.Inputs[0].Bip32Derivation, 1)

	// Assert: Input 1 is NOT decorated.
	require.Nil(t, packet.Inputs[1].WitnessUtxo)
	require.Nil(t, packet.Inputs[1].NonWitnessUtxo)
	require.Empty(t, packet.Inputs[1].Bip32Derivation)

	// Assert: Input 2 is decorated.
	require.NotNil(t, packet.Inputs[2].WitnessUtxo)
	require.Equal(t, int64(2000), packet.Inputs[2].WitnessUtxo.Value)
	require.Len(t, packet.Inputs[2].Bip32Derivation, 1)
}

// TestDecorateInputsErrUnknownRequired tests that DecorateInputs returns
// ErrNotMine when an input is unknown and skipUnknown is false.
func TestDecorateInputsErrUnknownRequired(t *testing.T) {
	t.Parallel()

	txHash := chainhash.Hash{1}
	unsignedTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  txHash,
				Index: 0,
			},
		}},
	}
	packet, err := psbt.NewFromUnsignedTx(unsignedTx)
	require.NoError(t, err)

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock TxDetails to return ErrTxNotFound.
	mocks.txStore.On(
		"TxDetails", mock.Anything, mock.Anything,
	).Return(nil, ErrTxNotFound)

	// Act: Call DecorateInputs with skipUnknown=false.
	_, err = w.DecorateInputs(t.Context(), packet, false)

	// Assert: Error is ErrNotMine.
	require.ErrorIs(t, err, ErrNotMine)
}

// TestDecorateInputsErrFetchFailed tests that DecorateInputs returns an error
// when fetching/validating a UTXO fails with a non-ErrNotMine error.
func TestDecorateInputsErrFetchFailed(t *testing.T) {
	t.Parallel()

	txHash := chainhash.Hash{1}
	unsignedTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  txHash,
				Index: 0,
			},
		}},
	}
	packet, err := psbt.NewFromUnsignedTx(unsignedTx)
	require.NoError(t, err)

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock TxDetails to return a database error.
	mocks.txStore.On(
		"TxDetails", mock.Anything, mock.Anything,
	).Return(nil, errDb)

	// Act: Call DecorateInputs (skipUnknown irrelevant for other errors).
	_, err = w.DecorateInputs(t.Context(), packet, true)

	// Assert: Error is errDb.
	require.ErrorIs(t, err, errDb)
}

// TestDecorateInputsErrDecorationFailed tests that DecorateInputs returns an
// error when the internal decorateInput call fails.
func TestDecorateInputsErrDecorationFailed(t *testing.T) {
	t.Parallel()

	// Arrange: Setup valid key/address/script for a known input.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)
	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	txHash := chainhash.Hash{1}
	unsignedTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  txHash,
				Index: 0,
			},
		}},
	}
	packet, err := psbt.NewFromUnsignedTx(unsignedTx)
	require.NoError(t, err)

	txDetails := &wtxmgr.TxDetails{
		TxRecord: wtxmgr.TxRecord{
			MsgTx: wire.MsgTx{
				TxOut: []*wire.TxOut{{
					Value: 1000, PkScript: p2wkhScript,
				}},
			},
		},
		Credits: []wtxmgr.CreditRecord{{Index: 0}},
	}

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock TxDetails success.
	mocks.txStore.On(
		"TxDetails", mock.Anything, mock.Anything,
	).Return(txDetails, nil)

	// Arrange: Mock AddressInfo to fail (causing decorateInput to fail).
	mocks.addrStore.On(
		"Address", mock.Anything, mock.Anything,
	).Return(nil, errDb)

	// Act: Call DecorateInputs.
	_, err = w.DecorateInputs(t.Context(), packet, true)

	// Assert: Error is errDb.
	require.ErrorIs(t, err, errDb)
}

// TestValidateFundIntentSuccess tests that validateFundIntent returns no error
// for valid funding intents.
func TestValidateFundIntentSuccess(t *testing.T) {
	t.Parallel()

	w, _ := testWalletWithMocks(t)

	// Arrange: Create a valid PSBT packet with one output (for auto
	// selection).
	tx := wire.NewMsgTx(2)
	tx.AddTxOut(&wire.TxOut{})
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	// Arrange: Create a FundIntent for automatic coin selection (no inputs
	// in packet).
	intentAuto := &FundIntent{
		Packet: packet,
	}

	// Arrange: Create a valid PSBT packet with one input and one output
	// (for manual selection).
	txWithInputs := wire.NewMsgTx(2)
	txWithInputs.AddTxIn(&wire.TxIn{})
	txWithInputs.AddTxOut(&wire.TxOut{})
	packetWithInputs, err := psbt.NewFromUnsignedTx(txWithInputs)
	require.NoError(t, err)

	// Arrange: Create a FundIntent for manual coin selection (inputs
	// present in packet).
	intentManual := &FundIntent{
		Packet: packetWithInputs,
	}

	// Act & Assert: Validate the auto selection intent. Expect no error.
	err = w.validateFundIntent(intentAuto)
	require.NoError(t, err)

	// Act & Assert: Validate the manual selection intent. Expect no error.
	err = w.validateFundIntent(intentManual)
	require.NoError(t, err)
}

// TestValidateFundIntentError tests that validateFundIntent returns expected
// errors for invalid funding intents.
func TestValidateFundIntentError(t *testing.T) {
	t.Parallel()

	w, _ := testWalletWithMocks(t)

	// Arrange: Helper function to create a PSBT packet with specified
	// inputs and outputs.
	createPacket := func(numInputs, numOutputs int) *psbt.Packet {
		tx := wire.NewMsgTx(2)
		for range numInputs {
			tx.AddTxIn(&wire.TxIn{})
		}

		for range numOutputs {
			tx.AddTxOut(&wire.TxOut{})
		}

		p, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)

		return p
	}

	// Arrange: Define test cases for various error scenarios.
	testCases := []struct {
		name        string
		intent      *FundIntent
		expectedErr error
	}{
		{
			name:        "nil intent",
			intent:      nil,
			expectedErr: ErrNilFundIntent,
		},
		{
			name:        "nil packet",
			intent:      &FundIntent{Packet: nil},
			expectedErr: ErrNilTxIntent,
		},
		{
			name:        "no inputs and no outputs",
			intent:      &FundIntent{Packet: createPacket(0, 0)},
			expectedErr: ErrPacketOutputsMissing,
		},
		{
			name: "inputs and policy conflict",
			intent: &FundIntent{
				Packet: createPacket(1, 1),
				Policy: &InputsPolicy{},
			},
			expectedErr: ErrInputsAndPolicy,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act: Call validateFundIntent with the configured
			// invalid intent.
			err := w.validateFundIntent(tc.intent)

			// Assert: Verify that the returned error matches the
			// expected error.
			require.ErrorIs(t, err, tc.expectedErr)
		})
	}
}

// TestCreateTxIntentAuto tests that createTxIntent correctly converts
// FundIntent to TxIntent for automatic coin selection.
func TestCreateTxIntentAuto(t *testing.T) {
	t.Parallel()

	w, _ := testWalletWithMocks(t)

	// Arrange: Create a PSBT packet with two outputs and no inputs,
	// which signals automatic coin selection.
	tx := wire.NewMsgTx(2)
	tx.AddTxOut(&wire.TxOut{Value: 1})
	tx.AddTxOut(&wire.TxOut{Value: 2})
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	// Arrange: Define the fee rate, coin selection policy, and change
	// source.
	feeRate := btcunit.NewSatPerKVByte(1000)
	policy := &InputsPolicy{
		MinConfs: 1,
	}
	changeSource := &ScopedAccount{}

	// Arrange: Create the FundIntent with the above parameters.
	intent := &FundIntent{
		Packet:       packet,
		Policy:       policy,
		FeeRate:      feeRate,
		Label:        "test",
		ChangeSource: changeSource,
	}

	// Act: Call createTxIntent to convert the FundIntent.
	txIntent := w.createTxIntent(intent)

	// Assert: Verify that the basic fields of the resulting TxIntent
	// match the input FundIntent.
	expectedOutputs := []wire.TxOut{{Value: 1}, {Value: 2}}
	require.Equal(t, expectedOutputs, txIntent.Outputs)
	require.Equal(t, feeRate, txIntent.FeeRate)
	require.Equal(t, "test", txIntent.Label)
	require.Equal(t, changeSource, txIntent.ChangeSource)

	// Assert: Verify that the Inputs field of TxIntent is of type
	// *InputsPolicy and matches the expected policy for auto selection.
	inputsPolicy, ok := txIntent.Inputs.(*InputsPolicy)
	require.True(t, ok)
	require.Equal(t, policy, inputsPolicy)
}

// TestCreateTxIntentManual tests that createTxIntent correctly converts
// FundIntent to TxIntent for manual coin selection.
func TestCreateTxIntentManual(t *testing.T) {
	t.Parallel()

	w, _ := testWalletWithMocks(t)

	// Arrange: Create a PSBT packet with two inputs and one output,
	// which signals manual coin selection.
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: 0},
	})
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: 1},
	})
	tx.AddTxOut(&wire.TxOut{Value: 1})

	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	// Arrange: Define the fee rate and change source. Policy is not needed
	// for manual selection.
	feeRate := btcunit.NewSatPerKVByte(1000)
	changeSource := &ScopedAccount{}

	// Arrange: Create the FundIntent with the above parameters.
	intent := &FundIntent{
		Packet:       packet,
		FeeRate:      feeRate,
		Label:        "manual",
		ChangeSource: changeSource,
	}

	// Act: Call createTxIntent to convert the FundIntent.
	txIntent := w.createTxIntent(intent)

	// Assert: Verify that the basic fields of the resulting TxIntent
	// match the input FundIntent.
	expectedOutputs := []wire.TxOut{{Value: 1}}
	require.Equal(t, expectedOutputs, txIntent.Outputs)
	require.Equal(t, feeRate, txIntent.FeeRate)
	require.Equal(t, "manual", txIntent.Label)
	require.Equal(t, changeSource, txIntent.ChangeSource)

	// Assert: Verify that the Inputs field of TxIntent is of type
	// *InputsManual and contains the expected UTXOs from the packet inputs.
	inputsManual, ok := txIntent.Inputs.(*InputsManual)
	require.True(t, ok)

	expectedUTXOs := []wire.OutPoint{{Index: 0}, {Index: 1}}
	require.Equal(t, expectedUTXOs, inputsManual.UTXOs)
}

// TestFindChangeIndex tests that findChangeIndex correctly locates the change
// output in the sorted PSBT packet.
func TestFindChangeIndex(t *testing.T) {
	t.Parallel()

	// Arrange: Create three distinct transaction outputs.
	out1 := &wire.TxOut{Value: 1000, PkScript: []byte{1}}
	out2 := &wire.TxOut{Value: 2000, PkScript: []byte{2}}

	// Identified as the change output.
	changeOut := &wire.TxOut{Value: 500, PkScript: []byte{3}}

	// Arrange: Setup a PSBT Packet where the outputs are sorted
	// differently, with the change output now at index 0: [changeOut,
	// out1, out2].
	packet := &psbt.Packet{
		UnsignedTx: &wire.MsgTx{
			TxOut: []*wire.TxOut{changeOut, out1, out2},
		},
	}

	// Act: Call findChangeIndex to locate the change output within the
	// sorted packet.
	idx, err := findChangeIndex(changeOut, packet)

	// Assert: Verify that no error occurred and the change index found in
	// the packet is 0, matching its new sorted position.
	require.NoError(t, err)
	require.Equal(t, int32(0), idx)

	// Act: Call findChangeIndex for the case with no change output (nil).
	idx, err = findChangeIndex(nil, packet)

	// Assert: Verify that no error occurred and the returned index is -1,
	// correctly indicating the absence of a change output.
	require.NoError(t, err)
	require.Equal(t, int32(-1), idx)

	// Act: Call findChangeIndex for a change output not present in the
	// packet.
	unknownOut := &wire.TxOut{Value: 9999, PkScript: []byte{4}}
	idx, err = findChangeIndex(unknownOut, packet)

	// Assert: Verify that no error occurred and the returned index is -1.
	require.NoError(t, err)
	require.Equal(t, int32(-1), idx)
}

// TestAddChangeOutputInfoSuccess tests that addChangeOutputInfo correctly adds
// derivation information to the change output.
func TestAddChangeOutputInfoSuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Setup keys and address.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)
	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	// Arrange: Create an AuthoredTx with a change output at index 0.
	changeOut := &wire.TxOut{
		Value:    500,
		PkScript: p2wkhScript,
	}
	authoredTx := &txauthor.AuthoredTx{
		Tx: &wire.MsgTx{
			TxOut: []*wire.TxOut{changeOut},
		},
		ChangeIndex: 0,
	}

	// Arrange: Create a PSBT packet with a corresponding output.
	packet, err := psbt.NewFromUnsignedTx(authoredTx.Tx)
	require.NoError(t, err)

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock Address lookup.
	mocks.addrStore.On(
		"Address", mock.Anything,
		mock.MatchedBy(func(addr btcutil.Address) bool {
			return addr.String() == p2wkhAddr.String()
		}),
	).Return(mocks.pubKeyAddr, nil)

	// Arrange: Mock ManagedPubKeyAddress methods.
	mocks.pubKeyAddr.On("Address").Return(p2wkhAddr)
	mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey)
	mocks.pubKeyAddr.On("PubKey").Return(pubKey)
	// Removed Imported() as addChangeOutputInfo does not call it.
	mocks.pubKeyAddr.On("DerivationInfo").Return(
		waddrmgr.KeyScopeBIP0084, waddrmgr.DerivationPath{}, true,
	)

	// Act: Call addChangeOutputInfo.
	err = w.addChangeOutputInfo(t.Context(), packet, authoredTx)

	// Assert: Verify success and that derivation info is added.
	require.NoError(t, err)
	require.Len(t, packet.Outputs[0].Bip32Derivation, 1)
	require.Equal(
		t, pubKey.SerializeCompressed(),
		packet.Outputs[0].Bip32Derivation[0].PubKey,
	)
}

// TestAddChangeOutputInfoErrScriptFail tests that addChangeOutputInfo returns
// an error if the script cannot be resolved (e.g. address lookup fails).
func TestAddChangeOutputInfoErrScriptFail(t *testing.T) {
	t.Parallel()

	// Arrange: Setup keys/address.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)
	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	// Arrange: Create authoredTx with change output.
	authoredTx := &txauthor.AuthoredTx{
		Tx: &wire.MsgTx{
			TxOut: []*wire.TxOut{{
				Value: 500, PkScript: p2wkhScript,
			}},
		},
		ChangeIndex: 0,
	}
	packet, err := psbt.NewFromUnsignedTx(authoredTx.Tx)
	require.NoError(t, err)

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock Address lookup to fail.
	mocks.addrStore.On(
		"Address", mock.Anything, mock.Anything,
	).Return(nil, errDb)

	// Act: Call addChangeOutputInfo.
	err = w.addChangeOutputInfo(t.Context(), packet, authoredTx)

	// Assert: Verify error (from ScriptForOutput).
	require.ErrorIs(t, err, errDb)
}

// TestAddChangeOutputInfoErrNotPubKey tests that addChangeOutputInfo returns
// ErrChangeAddressNotManagedPubKey if the change address is not a pubkey addr.
func TestAddChangeOutputInfoErrNotPubKey(t *testing.T) {
	t.Parallel()

	// Arrange: Setup keys/address.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)
	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	authoredTx := &txauthor.AuthoredTx{
		Tx: &wire.MsgTx{
			TxOut: []*wire.TxOut{{
				Value: 500, PkScript: p2wkhScript,
			}},
		},
		ChangeIndex: 0,
	}
	packet, err := psbt.NewFromUnsignedTx(authoredTx.Tx)
	require.NoError(t, err)

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock Address lookup to return a generic address.
	mocks.addrStore.On(
		"Address", mock.Anything, mock.Anything,
	).Return(mocks.addr, nil)
	mocks.addr.On("Address").Return(p2wkhAddr)

	// Act: Call addChangeOutputInfo.
	err = w.addChangeOutputInfo(t.Context(), packet, authoredTx)

	// Assert: Verify error (ErrNotPubKeyAddress from ScriptForOutput
	// check).
	require.ErrorIs(t, err, ErrNotPubKeyAddress)
}

// TestAddChangeOutputInfoErrDerivationUnknown tests that addChangeOutputInfo
// returns an error if the change address has no derivation info.
func TestAddChangeOutputInfoErrDerivationUnknown(t *testing.T) {
	t.Parallel()

	// Arrange: Setup keys/address.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)
	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	authoredTx := &txauthor.AuthoredTx{
		Tx: &wire.MsgTx{
			TxOut: []*wire.TxOut{{
				Value: 500, PkScript: p2wkhScript,
			}},
		},
		ChangeIndex: 0,
	}
	packet, err := psbt.NewFromUnsignedTx(authoredTx.Tx)
	require.NoError(t, err)

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock Address lookup.
	mocks.addrStore.On(
		"Address", mock.Anything, mock.Anything,
	).Return(mocks.pubKeyAddr, nil)

	// Arrange: Mock ManagedPubKeyAddress methods.
	mocks.pubKeyAddr.On("Address").Return(p2wkhAddr)
	mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey)
	// PubKey is not called because DerivationInfo returns false.
	// DerivationInfo returns false (unknown/imported).
	mocks.pubKeyAddr.On("DerivationInfo").Return(
		waddrmgr.KeyScope{}, waddrmgr.DerivationPath{}, false,
	)

	// Act: Call addChangeOutputInfo.
	err = w.addChangeOutputInfo(t.Context(), packet, authoredTx)

	// Assert: Verify error.
	require.ErrorContains(t, err, "change addr is an imported addr")
}

// TestPopulatePsbtPacketErrors tests error paths in populatePsbtPacket.
func TestPopulatePsbtPacketErrors(t *testing.T) {
	t.Parallel()

	// Arrange: Setup keys.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	// Input Address (Valid)
	addrIn, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)
	scriptIn, err := txscript.PayToAddrScript(addrIn)
	require.NoError(t, err)

	// Output Address (Valid struct, but will mock failure)
	addrOut, err := btcutil.NewAddressWitnessPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)
	scriptOut, err := txscript.PayToAddrScript(addrOut)
	require.NoError(t, err)

	txHash := chainhash.Hash{1}
	authoredTx := &txauthor.AuthoredTx{
		Tx: &wire.MsgTx{
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{
					Hash:  txHash,
					Index: 0,
				},
			}},
			TxOut: []*wire.TxOut{{
				Value:    500,
				PkScript: scriptOut,
			}},
		},
		ChangeIndex: 0, // Output 0 is change
	}
	packet := &psbt.Packet{}

	t.Run("DecorateInputs fails", func(t *testing.T) {
		t.Parallel()
		w, mocks := testWalletWithMocks(t)

		// Mock TxDetails failure (DecorateInputs ->
		// fetchAndValidateUtxo)
		mocks.txStore.On("TxDetails", mock.Anything, mock.Anything).
			Return(nil, errDb)

		_, _, err := w.populatePsbtPacket(
			t.Context(), packet, authoredTx,
		)
		require.ErrorIs(t, err, errDb)
	})

	t.Run("addChangeOutputInfo fails", func(t *testing.T) {
		t.Parallel()
		w, mocks := testWalletWithMocks(t)

		// Mock TxDetails success (DecorateInputs)
		txDetails := &wtxmgr.TxDetails{
			TxRecord: wtxmgr.TxRecord{
				MsgTx: wire.MsgTx{
					TxOut: []*wire.TxOut{{
						Value:    1000,
						PkScript: scriptIn,
					}},
				},
			},
			Credits: []wtxmgr.CreditRecord{{Index: 0}},
		}
		mocks.txStore.On("TxDetails", mock.Anything, mock.Anything).
			Return(txDetails, nil)

		// Mock Address lookup for Input (Success)
		mocks.addrStore.On(
			"Address", mock.Anything,
			mock.MatchedBy(func(a btcutil.Address) bool {
				return a.String() == addrIn.String()
			}),
		).Return(mocks.pubKeyAddr, nil)

		mocks.pubKeyAddr.On("Imported").Return(false)
		mocks.pubKeyAddr.On("DerivationInfo").Return(
			waddrmgr.KeyScopeBIP0084, waddrmgr.DerivationPath{},
			true,
		)
		mocks.pubKeyAddr.On("PubKey").Return(pubKey)
		mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey)

		// Mock Address lookup for Output (Fail)
		mocks.addrStore.On(
			"Address", mock.Anything,
			mock.MatchedBy(func(a btcutil.Address) bool {
				return a.String() == addrOut.String()
			}),
		).Return(nil, errDb)

		_, _, err := w.populatePsbtPacket(
			t.Context(), packet, authoredTx,
		)
		require.ErrorIs(t, err, errDb)
	})
}

// TestPopulatePsbtPacketSuccess tests that populatePsbtPacket correctly
// updates the packet with the transaction, decorates inputs, adds change info,
// and sorts the packet.
func TestPopulatePsbtPacketSuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Setup keys/address.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)
	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	// Arrange: Create AuthoredTx with 1 input and 2 outputs.
	// Output 0: Change (Value 1001)
	// Output 1: Payment (Value 1000)
	txHash := chainhash.Hash{}
	changeOut := &wire.TxOut{
		Value:    1001,
		PkScript: p2wkhScript,
	}
	paymentOut := &wire.TxOut{
		Value:    1000,
		PkScript: []byte{0x00}, // Simple script
	}

	authoredTx := &txauthor.AuthoredTx{
		Tx: &wire.MsgTx{
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{
					Hash:  txHash,
					Index: 0,
				},
			}},
			TxOut: []*wire.TxOut{changeOut, paymentOut},
		},
		ChangeIndex: 0,
	}

	// Arrange: Create empty packet (will be overwritten).
	packet := &psbt.Packet{}

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock TxDetails for input decoration.
	txDetails := &wtxmgr.TxDetails{
		TxRecord: wtxmgr.TxRecord{
			MsgTx: wire.MsgTx{
				TxOut: []*wire.TxOut{{
					Value: 1000, PkScript: p2wkhScript,
				}},
			},
		},
		Credits: []wtxmgr.CreditRecord{{Index: 0}},
	}
	mocks.txStore.On("TxDetails", mock.Anything, mock.Anything).
		Return(txDetails, nil)

	// Arrange: Mock Address lookup (used for both input decoration and
	// change output info).
	mocks.addrStore.On("Address", mock.Anything, mock.Anything).
		Return(mocks.pubKeyAddr, nil)

	// Arrange: Mock ManagedPubKeyAddress methods.
	mocks.pubKeyAddr.On("Imported").Return(false)
	mocks.pubKeyAddr.On("DerivationInfo").Return(
		waddrmgr.KeyScopeBIP0084, waddrmgr.DerivationPath{}, true,
	)
	mocks.pubKeyAddr.On("PubKey").Return(pubKey)
	mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey)
	mocks.pubKeyAddr.On("Address").Return(p2wkhAddr)

	// Act: Call populatePsbtPacket.
	updatedPacket, changeIdx, err := w.populatePsbtPacket(
		t.Context(), packet, authoredTx,
	)

	// Assert: Verify success.
	require.NoError(t, err)
	require.NotNil(t, updatedPacket)

	// Assert: Verify that the returned changeIdx points to the change
	// output. We know the change output has Value 1001.
	require.GreaterOrEqual(t, changeIdx, int32(0))
	require.Less(t, changeIdx, int32(len(updatedPacket.UnsignedTx.TxOut)))
	require.Equal(
		t, int64(1001), updatedPacket.UnsignedTx.TxOut[changeIdx].Value,
	)

	// Assert: Verify that the decorated output is indeed the change
	// output. The test setup ensures only the change address (p2wkhAddr)
	// returns derivation info in the mock. The payment output (simple
	// script) won't trigger address lookup that leads to derivation info
	// in this specific mock setup.
	require.Len(t, updatedPacket.Outputs[changeIdx].Bip32Derivation, 1)
	require.Equal(
		t, pubKey.SerializeCompressed(),
		updatedPacket.Outputs[changeIdx].Bip32Derivation[0].PubKey,
	)

	// Assert: Input decorated.
	require.Len(t, updatedPacket.Inputs, 1)
	require.NotNil(t, updatedPacket.Inputs[0].WitnessUtxo)
}

// TestFundPsbtWorkflow tests the high-level FundPsbt workflow with manual
// inputs.
func TestFundPsbtWorkflow(t *testing.T) {
	t.Parallel()

	// Arrange: Setup private and public keys for a P2WKH address.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)
	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	// Arrange: Create a PSBT with one input and one output to simulate a
	// transaction that needs funding and decoration.
	// Input: 1.0 BTC (100,000,000 sat)
	// Output: 0.5 BTC (50,000,000 sat)
	// Fee: ~1000 sat (simplified)
	// Expected Change: ~0.5 BTC (after fees)
	txHash := chainhash.Hash{1}
	outPoint := wire.OutPoint{Hash: txHash, Index: 0}
	inputAmount := btcutil.Amount(100000000)
	outputAmount := btcutil.Amount(50000000)

	unsignedTx := wire.NewMsgTx(2)
	unsignedTx.AddTxIn(&wire.TxIn{PreviousOutPoint: outPoint})
	unsignedTx.AddTxOut(&wire.TxOut{
		Value: int64(outputAmount), PkScript: p2wkhScript,
	})

	packet, err := psbt.NewFromUnsignedTx(unsignedTx)
	require.NoError(t, err)

	// Arrange: Mock data for UTXO and Transaction Details required by
	// internal calls.
	credit := &wtxmgr.Credit{
		OutPoint: outPoint,
		Amount:   inputAmount,
		PkScript: p2wkhScript,
	}

	txDetails := &wtxmgr.TxDetails{
		TxRecord: wtxmgr.TxRecord{
			MsgTx: wire.MsgTx{
				TxOut: []*wire.TxOut{
					{
						Value:    int64(inputAmount),
						PkScript: p2wkhScript,
					},
				},
			},
		},
		Credits: []wtxmgr.CreditRecord{
			{Index: 0},
		},
	}

	// Arrange: Define the FundIntent for the PSBT, including fee rate and
	// change source.
	intent := &FundIntent{
		Packet:  packet,
		FeeRate: btcunit.NewSatPerKVByte(1000),
		ChangeSource: &ScopedAccount{
			AccountName: "default",
			KeyScope:    waddrmgr.KeyScopeBIP0084,
		},
	}

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock the internal dependencies for the FundPsbt workflow.
	// 1. Mock `txStore.GetUtxo` for `createManualInputSource`:
	//    Expect a call with any context and the specified outpoint,
	//    returning our predefined credit and no error.
	mocks.txStore.On("GetUtxo", mock.Anything, outPoint).Return(credit, nil)

	// 2. Mock `addrStore.FetchScopedKeyManager` to retrieve the account
	//    manager:
	//    Expect a call with the BIP0084 key scope, returning the mock
	//    account manager and no error.
	mocks.addrStore.On(
		"FetchScopedKeyManager", waddrmgr.KeyScopeBIP0084,
	).Return(mocks.accountManager, nil)

	// 3. Mock `accountManager.LookupAccount` for the default account:
	//    Expect a call with any context and "default" account name,
	//    returning the default account number and no error.
	mocks.accountManager.On("LookupAccount", mock.Anything, "default").
		Return(uint32(waddrmgr.DefaultAccountNum), nil)

	// 4. Mock `accountManager.AccountProperties` to return properties for
	//    the default account:
	//    Expect a call with any context and the default account number,
	//    returning predefined account properties and no error.
	mocks.accountManager.On(
		"AccountProperties",
		mock.Anything,
		uint32(waddrmgr.DefaultAccountNum),
	).Return(&waddrmgr.AccountProperties{
		AccountName: "default",
		KeyScope:    waddrmgr.KeyScopeBIP0084,
	}, nil)

	// 5. Mock `accountManager.NextInternalAddresses` to generate a change
	//    address:
	//    Expect a call to generate one internal address for the default
	//    account, returning our mock managed address and no error.
	changeAddr := p2wkhAddr // Reusing p2wkhAddr for simplicity as change
	mockManagedAddr := mocks.pubKeyAddr
	mocks.accountManager.On(
		"NextInternalAddresses",
		mock.Anything,
		uint32(waddrmgr.DefaultAccountNum),
		uint32(1),
	).Return([]waddrmgr.ManagedAddress{mockManagedAddr}, nil)

	// 6. Mock `mockManagedAddr.Address` to return the change address:
	//    Expect a call to get the address from the mock managed address,
	//    returning our predefined P2WKH address.
	mockManagedAddr.On("Address").Return(changeAddr)

	// 7. Mock `txStore.TxDetails` for `fetchAndValidateUtxo` during
	//    `DecorateInputs`:
	//    Expect a call to retrieve transaction details for the input's
	//    hash, returning our predefined `txDetails` and no error.
	mocks.txStore.On(
		"TxDetails",
		mock.Anything,
		mock.MatchedBy(func(h *chainhash.Hash) bool {
			return h.IsEqual(&txHash)
		}),
	).Return(txDetails, nil)

	// 8. Mock `addrStore.Address` for `decorateInput` during
	//    `DecorateInputs`:
	//    Expect a call to look up the address by script, returning our
	//    mock managed public key address and no error.
	mocks.addrStore.On(
		"Address",
		mock.Anything,
		mock.MatchedBy(func(addr btcutil.Address) bool {
			return addr.String() == p2wkhAddr.String()
		}),
	).Return(mocks.pubKeyAddr, nil)

	// 9. Mock `ManagedPubKeyAddress` methods for `decorateInput`:
	//    Expect calls to get imported status, derivation info, public key,
	//    and address type, returning predefined values.
	mocks.pubKeyAddr.On("Imported").Return(false)
	mocks.pubKeyAddr.On("DerivationInfo").Return(
		waddrmgr.KeyScopeBIP0084, waddrmgr.DerivationPath{}, true,
	)
	mocks.pubKeyAddr.On("PubKey").Return(pubKey)
	mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey)

	// Act: Execute the FundPsbt workflow with the configured intent.
	fundedPacket, changeIndex, err := w.FundPsbt(t.Context(), intent)

	// Assert: Verify that no error occurred, a funded PSBT packet is
	// returned, and a valid change index is provided.
	require.NoError(t, err)
	require.NotNil(t, fundedPacket)
	require.GreaterOrEqual(t, changeIndex, int32(0))
}

// TestFundPsbtDecorateFailure tests that FundPsbt returns an error if the
// internal DecorateInputs call fails (e.g. due to database error).
func TestFundPsbtDecorateFailure(t *testing.T) {
	t.Parallel()

	// Arrange: Setup keys/address.
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)
	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	// Arrange: Create packet with 1 input.
	txHash := chainhash.Hash{1}
	outPoint := wire.OutPoint{Hash: txHash, Index: 0}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: outPoint})
	tx.AddTxOut(&wire.TxOut{Value: 90000, PkScript: p2wkhScript})
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	// Arrange: Intent with manual inputs (so CreateTransaction uses
	// GetUtxo).
	intent := &FundIntent{
		Packet:  packet,
		FeeRate: btcunit.NewSatPerKVByte(1000),
		ChangeSource: &ScopedAccount{
			AccountName: "default",
			KeyScope:    waddrmgr.KeyScopeBIP0084,
		},
	}

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock GetUtxo for CreateTransaction (Success).
	credit := &wtxmgr.Credit{
		OutPoint: outPoint,
		Amount:   100000,
		PkScript: p2wkhScript,
	}
	mocks.txStore.On("GetUtxo", mock.Anything, outPoint).Return(credit, nil)

	// Arrange: Mock TxDetails for DecorateInputs (Failure).
	// This triggers the error in populatePsbtPacket -> DecorateInputs.
	mocks.txStore.On(
		"TxDetails", mock.Anything,
		mock.MatchedBy(func(h *chainhash.Hash) bool {
			return h.IsEqual(&txHash)
		}),
	).Return(nil, errDb)

	// Arrange: Mock account manager for change address generation, which is
	// required because the input (100k) exceeds the output (90k) + fees.
	mocks.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(mocks.accountManager, nil)
	mocks.accountManager.On("LookupAccount", mock.Anything, "default").
		Return(uint32(waddrmgr.DefaultAccountNum), nil)
	mocks.accountManager.On(
		"AccountProperties", mock.Anything,
		uint32(waddrmgr.DefaultAccountNum),
	).Return(&waddrmgr.AccountProperties{
		AccountName: "default",
		KeyScope:    waddrmgr.KeyScopeBIP0084,
	}, nil)
	// Change address generation.
	mocks.accountManager.On(
		"NextInternalAddresses", mock.Anything, mock.Anything,
		mock.Anything,
	).Return([]waddrmgr.ManagedAddress{mocks.pubKeyAddr}, nil)
	mocks.pubKeyAddr.On("Address").Return(p2wkhAddr)

	// Act: FundPsbt.
	_, _, err = w.FundPsbt(t.Context(), intent)

	// Assert: Should fail due to DecorateInputs error.
	require.ErrorIs(t, err, errDb)
}

// TestFundPsbtErrors tests various error conditions in FundPsbt.
func TestFundPsbtErrors(t *testing.T) {
	t.Parallel()

	// Arrange: Common intent setup (auto coin selection).
	tx := wire.NewMsgTx(2)
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x00}})
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	intent := &FundIntent{
		Packet:  packet,
		FeeRate: btcunit.NewSatPerKVByte(1000),
		// Policy implies auto selection
		Policy: &InputsPolicy{
			Source: &ScopedAccount{
				AccountName: "default",
				KeyScope:    waddrmgr.KeyScopeBIP0084,
			},
		},
	}

	t.Run("validate intent fails", func(t *testing.T) {
		t.Parallel()
		w, _ := testWalletWithMocks(t)
		// Invalid intent (nil packet)
		_, _, err := w.FundPsbt(t.Context(), &FundIntent{})
		require.ErrorIs(t, err, ErrNilTxIntent)
	})

	t.Run("CreateTransaction fails", func(t *testing.T) {
		t.Parallel()
		w, mocks := testWalletWithMocks(t)

		// Mock CreateTransaction failure via Account lookup failure
		mocks.addrStore.On("FetchScopedKeyManager", mock.Anything).
			Return(nil, errDb)

		_, _, err := w.FundPsbt(t.Context(), intent)
		// AccountNumber failure is wrapped in ErrAccountNotFound by
		// prepareTxAuthSources.
		require.ErrorIs(t, err, ErrAccountNotFound)
	})
}

// TestParseBip32Path tests that parseBip32Path correctly parses valid BIP32
// paths and returns the appropriate KeyScope and DerivationPath, while also
// flagging invalid paths.
func TestParseBip32Path(t *testing.T) {
	t.Parallel()

	// Use mainnet params for testing (HDCoinType = 0).
	chainParams := &chaincfg.MainNetParams
	w := &Wallet{chainParams: chainParams}

	hardened := func(i uint32) uint32 {
		return i + hdkeychain.HardenedKeyStart
	}

	tests := []struct {
		name        string
		path        []uint32
		wantPath    BIP32Path
		expectedErr error // Use error type for require.ErrorIs
	}{
		{
			name: "valid BIP44",
			path: []uint32{
				hardened(44), hardened(0), hardened(0), 0, 0,
			},
			wantPath: BIP32Path{
				KeyScope: waddrmgr.KeyScopeBIP0044,
				DerivationPath: waddrmgr.DerivationPath{
					Account: 0,
					Branch:  0,
					Index:   0,
				},
			},
		},
		{
			name: "valid BIP84",
			path: []uint32{
				hardened(84), hardened(0), hardened(1), 0, 5,
			},
			wantPath: BIP32Path{
				KeyScope: waddrmgr.KeyScopeBIP0084,
				DerivationPath: waddrmgr.DerivationPath{
					Account: 1,
					Branch:  0,
					Index:   5,
				},
			},
		},
		{
			name:        "invalid length",
			path:        []uint32{hardened(84)},
			expectedErr: ErrInvalidBip32PathLength,
		},
		{
			name: "unhardened purpose",
			path: []uint32{
				84, hardened(0), hardened(0), 0, 0,
			},
			expectedErr: ErrInvalidBip32PathElementHardened,
		},
		{
			name: "unhardened coin type",
			path: []uint32{
				hardened(84), 0, hardened(0), 0, 0,
			},
			expectedErr: ErrInvalidBip32PathElementHardened,
		},
		{
			name: "unhardened account",
			path: []uint32{
				hardened(84), hardened(0), 0, 0, 0,
			},
			expectedErr: ErrInvalidBip32PathElementHardened,
		},
		{
			name: "coin type mismatch",
			path: []uint32{
				hardened(84), hardened(1), hardened(0), 0, 0,
			},
			expectedErr: ErrInvalidBip32DerivationCoinType,
		},
		{
			name: "unknown purpose (now allowed in parseBip32Path)",
			path: []uint32{
				hardened(999), hardened(0), hardened(0), 0, 0,
			},
			wantPath: BIP32Path{
				KeyScope: waddrmgr.KeyScope{
					Purpose: 999, Coin: 0,
				},
				DerivationPath: waddrmgr.DerivationPath{
					Account: 0,
					Branch:  0,
					Index:   0,
				},
			},
			expectedErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act: Call parseBip32Path with the test path.
			gotPath, err := w.parseBip32Path(tc.path)

			// Assert: Verify that the function returns the expected
			// error (if any) or that the parsed path components
			// (KeyScope, DerivationPath) match the expected
			// structure.
			require.ErrorIs(t, err, tc.expectedErr)
			require.Equal(t, tc.wantPath, gotPath)
		})
	}
}

// TestAddressTypeFromPurpose tests that addressTypeFromPurpose returns the
// correct AddressType for supported BIP32 purposes and returns an error for
// unknown purposes.
func TestAddressTypeFromPurpose(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		purpose     uint32
		want        waddrmgr.AddressType
		expectedErr error
	}{
		{
			name:    "BIP44",
			purpose: waddrmgr.KeyScopeBIP0044.Purpose,
			want:    waddrmgr.PubKeyHash,
		},
		{
			name:    "BIP49",
			purpose: waddrmgr.KeyScopeBIP0049Plus.Purpose,
			want:    waddrmgr.NestedWitnessPubKey,
		},
		{
			name:    "BIP84",
			purpose: waddrmgr.KeyScopeBIP0084.Purpose,
			want:    waddrmgr.WitnessPubKey,
		},
		{
			name:    "BIP86",
			purpose: waddrmgr.KeyScopeBIP0086.Purpose,
			want:    waddrmgr.TaprootPubKey,
		},
		{
			name:        "unknown",
			purpose:     999,
			expectedErr: ErrUnknownBip32Purpose,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act: Call addressTypeFromPurpose with the test
			// purpose.
			got, err := addressTypeFromPurpose(tc.purpose)

			// Assert: Verify that the returned address type matches
			// the expected type for the given purpose, or that the
			// expected error is returned for unknown purposes.
			require.ErrorIs(t, err, tc.expectedErr)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestShouldSkipInput tests that shouldSkipInput correctly identifies inputs
// that should be skipped during signing (e.g., finalized inputs, inputs with
// no derivation info) and those that should be processed.
func TestShouldSkipInput(t *testing.T) {
	t.Parallel()

	// Define shared variables for long literals to satisfy linter.
	taprootDerivation := []*psbt.TaprootBip32Derivation{{
		XOnlyPubKey: []byte{0x01},
	}}

	tests := []struct {
		name     string
		pInput   *psbt.PInput
		expected bool
	}{
		{
			name: "finalized input should be skipped",
			pInput: &psbt.PInput{
				FinalScriptWitness: []byte{1, 2, 3},
			},
			expected: true,
		},
		{
			name: "no derivation info should be skipped",
			pInput: &psbt.PInput{
				FinalScriptWitness:     nil,
				Bip32Derivation:        nil,
				TaprootBip32Derivation: nil,
			},
			expected: true,
		},
		{
			name: "valid BIP32 derivation, not skipped",
			pInput: &psbt.PInput{
				Bip32Derivation: []*psbt.Bip32Derivation{{
					PubKey: []byte{0x01},
				}},
			},
			expected: false,
		},
		{
			name: "valid Taproot derivation, not skipped",
			pInput: &psbt.PInput{
				TaprootBip32Derivation: taprootDerivation,
			},
			expected: false,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act: Call shouldSkipInput with the configured PSBT
			// input.
			result := shouldSkipInput(tc.pInput, i)

			// Assert: Verify that the returned boolean matches the
			// expectation (true for skippable inputs, false
			// otherwise).
			require.Equal(t, tc.expected, result)
		})
	}
}

// TestShouldSkipSigningError tests that shouldSkipSigningError correctly
// determines whether a signing error is non-critical (and thus the input can
// be skipped) or critical.
func TestShouldSkipSigningError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "already signed error should be skipped",
			err:      errAlreadySigned,
			expected: true,
		},
		{
			name:     "compute raw sig error should be skipped",
			err:      fmt.Errorf("wrapped: %w", errComputeRawSig),
			expected: true,
		},
		{
			name: "unknown BIP32 purpose error should be " +
				"skipped",
			err:      ErrUnknownBip32Purpose,
			expected: true,
		},

		{
			name:     "generic error should not be skipped",
			err:      errDb,
			expected: false,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act: Call shouldSkipSigningError with the test error.
			result := shouldSkipSigningError(tc.err, i)

			// Assert: Verify that the function correctly identifies
			// whether the error should cause the input to be
			// skipped (true) or treated as a failure (false).
			require.Equal(t, tc.expected, result)
		})
	}
}

// TestValidateDerivation tests that validateDerivation correctly identifies the
// derivation type (Taproot vs. BIP32) and validates that there are no
// conflicting or multiple derivation paths.
func TestValidateDerivation(t *testing.T) {
	t.Parallel()

	// Define shared variables for long literals.
	taprootDerivation := []*psbt.TaprootBip32Derivation{{}}
	multiTapDerivation := []*psbt.TaprootBip32Derivation{{}, {}}
	multiBip32Derivation := []*psbt.Bip32Derivation{{}, {}}
	singleBip32Derivation := []*psbt.Bip32Derivation{{}}

	// Arrange: Define test cases for derivation validation.
	tests := []struct {
		name      string
		pInput    *psbt.PInput
		isTaproot bool
		err       error
	}{
		{
			name: "single BIP32 derivation",
			pInput: &psbt.PInput{
				Bip32Derivation: []*psbt.Bip32Derivation{{}},
			},
			isTaproot: false,
			err:       nil,
		},
		{
			name: "single Taproot derivation",
			pInput: &psbt.PInput{
				TaprootBip32Derivation: taprootDerivation,
			},
			isTaproot: true,
			err:       nil,
		},
		{
			name: "multiple BIP32 derivations error",
			pInput: &psbt.PInput{
				Bip32Derivation: multiBip32Derivation,
			},
			isTaproot: false,
			err:       ErrUnsupportedMultipleBip32Derivation,
		},
		{
			name: "multiple Taproot derivations error",
			pInput: &psbt.PInput{
				TaprootBip32Derivation: multiTapDerivation,
			},
			isTaproot: false,
			err:       ErrUnsupportedMultipleTaprootDerivation,
		},
		{
			name: "ambiguous derivation",
			pInput: &psbt.PInput{
				Bip32Derivation:        singleBip32Derivation,
				TaprootBip32Derivation: taprootDerivation,
			},
			isTaproot: false,
			err:       ErrAmbiguousDerivation,
		},
		{
			name:      "no derivation info (valid)",
			pInput:    &psbt.PInput{},
			isTaproot: false,
			err:       nil,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Act: Call validateDerivation with the configured
			// input to check for validity and determine if it's a
			// Taproot input.
			isTaproot, err := validateDerivation(tc.pInput, i)

			// Assert: Verify that the returned error matches the
			// expected error (e.g., for ambiguous or multiple
			// derivations) and that the Taproot flag is set
			// correctly for valid inputs.
			require.ErrorIs(t, err, tc.err)
			require.Equal(t, tc.isTaproot, isTaproot)
		})
	}
}

// TestFetchPsbtUtxo tests that fetchPsbtUtxo correctly prioritizes WitnessUtxo
// over NonWitnessUtxo when retrieving the UTXO for a PSBT input, and safely
// handles missing data.
func TestFetchPsbtUtxo(t *testing.T) {
	t.Parallel()

	// Arrange: Create dummy UTXOs for testing.
	witnessUtxo := &wire.TxOut{Value: 1000, PkScript: []byte{0x00}}
	nonWitnessUtxo := &wire.TxOut{Value: 2000, PkScript: []byte{0x01}}

	// Arrange: Create a transaction that has the nonWitnessUtxo at index 0
	tx := wire.NewMsgTx(2)
	tx.AddTxOut(nonWitnessUtxo)

	// Arrange: Define test cases for fetching UTXOs.
	tests := []struct {
		name        string
		packet      *psbt.Packet
		inputIdx    int
		expected    *wire.TxOut
		expectedErr error
	}{
		{
			name: "prioritize WitnessUtxo",
			// Arrange: PSBT input with both WitnessUtxo and
			// NonWitnessUtxo.
			packet: &psbt.Packet{
				UnsignedTx: &wire.MsgTx{
					TxIn: []*wire.TxIn{{}},
				},
				Inputs: []psbt.PInput{{
					WitnessUtxo:    witnessUtxo,
					NonWitnessUtxo: tx,
				}},
			},
			inputIdx: 0,
			// Assert: Expect WitnessUtxo to be returned.
			expected:    witnessUtxo,
			expectedErr: nil,
		},
		{
			name: "fallback to NonWitnessUtxo",
			// Arrange: PSBT input with only NonWitnessUtxo.
			packet: &psbt.Packet{
				UnsignedTx: &wire.MsgTx{
					TxIn: []*wire.TxIn{{
						PreviousOutPoint: wire.OutPoint{
							Index: 0,
						},
					}},
				},
				Inputs: []psbt.PInput{{
					WitnessUtxo:    nil,
					NonWitnessUtxo: tx,
				}},
			},
			inputIdx: 0,
			// Assert: Expect NonWitnessUtxo to be returned.
			expected:    nonWitnessUtxo,
			expectedErr: nil,
		},
		{
			name: "missing all utxo info",
			packet: &psbt.Packet{
				UnsignedTx: &wire.MsgTx{
					TxIn: []*wire.TxIn{{}},
				},
				Inputs: []psbt.PInput{{
					WitnessUtxo:    nil,
					NonWitnessUtxo: nil,
				}},
			},
			inputIdx:    0,
			expected:    nil,
			expectedErr: ErrInputMissingUtxoInfo,
		},
		{
			name: "input index out of bounds",
			packet: &psbt.Packet{
				UnsignedTx: &wire.MsgTx{
					TxIn: []*wire.TxIn{},
				},
				Inputs: []psbt.PInput{},
			},
			inputIdx:    0,
			expected:    nil,
			expectedErr: ErrPsbtInputIndexOutOfBounds,
		},
		{
			name: "prevout index out of bounds",
			packet: &psbt.Packet{
				UnsignedTx: &wire.MsgTx{
					TxIn: []*wire.TxIn{{
						PreviousOutPoint: wire.OutPoint{
							Index: 99,
						},
					}},
				},
				Inputs: []psbt.PInput{{
					NonWitnessUtxo: tx,
				}},
			},
			inputIdx:    0,
			expected:    nil,
			expectedErr: ErrPrevOutIndexOutOfBounds,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Act: Call fetchPsbtUtxo with the configured packet
			// and input index.
			got, err := fetchPsbtUtxo(tc.packet, tc.inputIdx)

			// Assert: Verify that the function returns the correct
			// UTXO (or nil on error) and the expected error
			// status.
			require.ErrorIs(t, err, tc.expectedErr)
			require.Equal(t, tc.expected, got)
		})
	}
}

// TestCheckTaprootScriptSpendSig tests that checkTaprootScriptSpendSig
// correctly detects if a Taproot script spend signature already exists for the
// given key and leaf.
func TestCheckTaprootScriptSpendSig(t *testing.T) {
	t.Parallel()

	// Arrange: Create dummy public key and leaf hash for Taproot
	// signatures.
	xOnlyPubKey := bytes.Repeat([]byte{0x01}, 32)
	leafHash := bytes.Repeat([]byte{0x02}, 32)

	// Pre-define complex slice literals.
	diffKeySig := []*psbt.TaprootScriptSpendSig{
		{
			XOnlyPubKey: bytes.Repeat(
				[]byte{0x03}, 32,
			),
			LeafHash: leafHash,
		},
	}

	sameKeySig := []*psbt.TaprootScriptSpendSig{
		{
			XOnlyPubKey: xOnlyPubKey,
			LeafHash:    leafHash,
		},
	}

	// Arrange: Define test cases for checking existing Taproot script
	// spend signatures.
	tests := []struct {
		name          string
		pInput        *psbt.PInput
		tapDerivation *psbt.TaprootBip32Derivation
		err           error
	}{
		{
			name: "no existing signature",
			// Arrange: No TaprootScriptSpendSig in the input.
			pInput: &psbt.PInput{
				TaprootScriptSpendSig: nil,
			},
			tapDerivation: &psbt.TaprootBip32Derivation{
				XOnlyPubKey: xOnlyPubKey,
				LeafHashes:  [][]byte{leafHash},
			},
			err: nil,
		},
		{
			name: "existing signature for different key",
			// Arrange: A TaprootScriptSpendSig exists, but for a
			// different XOnlyPubKey.
			pInput: &psbt.PInput{
				TaprootScriptSpendSig: diffKeySig,
			},
			tapDerivation: &psbt.TaprootBip32Derivation{
				XOnlyPubKey: xOnlyPubKey,
				LeafHashes:  [][]byte{leafHash},
			},
			err: nil,
		},
		{
			name: "existing signature for same key and leaf",
			// Arrange: A matching TaprootScriptSpendSig already
			// exists.
			pInput: &psbt.PInput{
				TaprootScriptSpendSig: sameKeySig,
			},
			tapDerivation: &psbt.TaprootBip32Derivation{
				XOnlyPubKey: xOnlyPubKey,
				LeafHashes:  [][]byte{leafHash},
			},
			// Assert: Expect errAlreadySigned.
			err: errAlreadySigned,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Act: Call checkTaprootScriptSpendSig with the
			// configured input and derivation info.
			err := checkTaprootScriptSpendSig(
				tc.pInput, tc.tapDerivation,
			)

			// Assert: Verify that the function returns an error
			// only if a valid signature for the same key and leaf
			// hash already exists.
			require.ErrorIs(t, err, tc.err)
		})
	}
}

// TestAddTaprootSigToPInput tests that addTaprootSigToPInput correctly adds a
// generated Taproot signature to the PSBT input, handling both Key Spend and
// Script Spend paths.
func TestAddTaprootSigToPInput(t *testing.T) {
	t.Parallel()

	// Arrange: Define dummy signature, public key, and leaf hash.
	sig := []byte{0x01, 0x02}
	xOnlyPubKey := bytes.Repeat([]byte{0x03}, 32)
	leafHash := bytes.Repeat([]byte{0x04}, 32)

	// Helper to create signature with appended sighash
	sigWithHash := append(slices.Clone(sig), byte(txscript.SigHashAll))

	// Arrange: Define test cases for adding Taproot signatures.
	tests := []struct {
		name           string
		initialPInput  *psbt.PInput
		sighashType    txscript.SigHashType
		details        TaprootSpendDetails
		tapDerivation  *psbt.TaprootBip32Derivation
		expectedPInput *psbt.PInput
	}{
		{
			name: "key path spend default sighash",
			// Arrange: Initial empty PSBT input.
			initialPInput: &psbt.PInput{},
			sighashType:   txscript.SigHashDefault,
			// Arrange: Key path spend details.
			details: TaprootSpendDetails{
				SpendPath: KeyPathSpend,
			},
			tapDerivation: nil, // Not used for key path spend
			// Assert: Expect TaprootKeySpendSig to be set.
			expectedPInput: &psbt.PInput{
				TaprootKeySpendSig: sig,
			},
		},
		{
			name: "key path spend non-default sighash",
			// Arrange: Initial empty PSBT input.
			initialPInput: &psbt.PInput{},
			sighashType:   txscript.SigHashAll,
			// Arrange: Key path spend details.
			details: TaprootSpendDetails{
				SpendPath: KeyPathSpend,
			},
			tapDerivation: nil,
			// Assert: Expect TaprootKeySpendSig with appended
			// sighash.
			expectedPInput: &psbt.PInput{
				TaprootKeySpendSig: sigWithHash,
			},
		},
		{
			name: "script path spend",
			// Arrange: Initial PSBT input with default SighashType.
			initialPInput: &psbt.PInput{
				SighashType: txscript.SigHashDefault,
			},
			sighashType: txscript.SigHashDefault,
			// Arrange: Script path spend details.
			details: TaprootSpendDetails{
				SpendPath: ScriptPathSpend,
			},
			// Arrange: Taproot BIP32 derivation with XOnlyPubKey
			// and LeafHashes.
			tapDerivation: &psbt.TaprootBip32Derivation{
				XOnlyPubKey: xOnlyPubKey,
				LeafHashes:  [][]byte{leafHash},
			},
			// Assert: Expect TaprootScriptSpendSig to be appended.
			//nolint:lll
			expectedPInput: &psbt.PInput{
				SighashType: txscript.SigHashDefault,
				TaprootScriptSpendSig: []*psbt.TaprootScriptSpendSig{{
					XOnlyPubKey: xOnlyPubKey,
					LeafHash:    leafHash,
					Signature:   sig,
					SigHash:     txscript.SigHashDefault,
				}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Arrange: Create a copy of the initial input to ensure
			// test isolation and avoid side effects.
			pInput := *tc.initialPInput

			// Act: Call addTaprootSigToPInput to add the signature
			// to the PSBT input.
			addTaprootSigToPInput(
				&pInput, sig, tc.sighashType, tc.details,
				tc.tapDerivation,
			)

			// Assert: Verify that the resulting PSBT input matches
			// the expected state.
			require.Equal(t, tc.expectedPInput, &pInput)
		})
	}
}

// TestAddBip32SigToPInput tests that addBip32SigToPInput correctly adds a
// generated BIP32 signature to the PSBT input's partial signatures, appending
// the sighash type if necessary.
func TestAddBip32SigToPInput(t *testing.T) {
	t.Parallel()

	// Arrange: Define dummy signature and public key.
	sig := []byte{0x01, 0x02}
	pubKey := bytes.Repeat([]byte{0x03}, 33)

	// Helper to create signature with appended sighash
	sigWithHash := append(slices.Clone(sig), byte(txscript.SigHashAll))

	// Arrange: Define test cases for adding BIP32 signatures.
	tests := []struct {
		name           string
		initialPInput  *psbt.PInput
		sighashType    txscript.SigHashType
		addrType       waddrmgr.AddressType
		derivation     *psbt.Bip32Derivation
		expectedPInput *psbt.PInput
	}{
		{
			name: "legacy p2pkh (no sighash append)",
			// Arrange: Initial empty PSBT input.
			initialPInput: &psbt.PInput{},
			sighashType:   txscript.SigHashAll,
			// Arrange: Public Key Hash address type.
			addrType: waddrmgr.PubKeyHash,
			// Arrange: BIP32 derivation with PubKey.
			derivation: &psbt.Bip32Derivation{
				PubKey: pubKey,
			},
			// Assert: Expect PartialSigs to be appended with raw
			// sig.
			expectedPInput: &psbt.PInput{
				PartialSigs: []*psbt.PartialSig{{
					PubKey:    pubKey,
					Signature: sig,
				}},
			},
		},
		{
			name: "segwit p2wkh (append sighash)",
			// Arrange: Initial empty PSBT input.
			initialPInput: &psbt.PInput{},
			sighashType:   txscript.SigHashAll,
			// Arrange: Witness Public Key Hash address type.
			addrType: waddrmgr.WitnessPubKey,
			// Arrange: BIP32 derivation with PubKey.
			derivation: &psbt.Bip32Derivation{
				PubKey: pubKey,
			},
			// Assert: Expect PartialSigs to be appended with sig +
			// sighash.
			expectedPInput: &psbt.PInput{
				PartialSigs: []*psbt.PartialSig{{
					PubKey:    pubKey,
					Signature: sigWithHash,
				}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Arrange: Create a copy of the initial input to ensure
			// test isolation.
			pInput := *tc.initialPInput

			// Act: Call addBip32SigToPInput to add the signature
			// to the PSBT input.
			addBip32SigToPInput(
				&pInput, sig, tc.sighashType, tc.derivation,
				tc.addrType,
			)

			// Assert: Verify that the resulting PSBT input matches
			// the expected state.
			require.Equal(t, tc.expectedPInput, &pInput)
		})
	}
}

// TestCreateTaprootSpendDetails tests that createTaprootSpendDetails correctly
// constructs the TaprootSpendDetails required for signing, handling both Key
// Path and Script Path spends.
func TestCreateTaprootSpendDetails(t *testing.T) {
	t.Parallel()

	// Helpers
	xOnlyPubKey := bytes.Repeat([]byte{0x01}, 32)
	leafHash := bytes.Repeat([]byte{0x02}, 32)
	leafScript := []byte{0x51} // OP_TRUE
	merkleRoot := bytes.Repeat([]byte{0x03}, 32)

	// Calculate expected hash for success case
	tapLeaf := txscript.NewBaseTapLeaf(leafScript)
	tapHash := tapLeaf.TapHash()
	leafHashCalculated := tapHash[:]

	// Define slice literals.
	tapLeafScriptSuccess := []*psbt.TaprootTapLeafScript{{
		LeafVersion: txscript.BaseLeafVersion,
		Script:      leafScript,
	}}

	tests := []struct {
		name          string
		pInput        *psbt.PInput
		tapDerivation *psbt.TaprootBip32Derivation
		expected      TaprootSpendDetails
		err           error
	}{
		{
			name: "key path spend success",
			pInput: &psbt.PInput{
				TaprootMerkleRoot: merkleRoot,
			},
			tapDerivation: &psbt.TaprootBip32Derivation{
				XOnlyPubKey: xOnlyPubKey,
				LeafHashes:  nil, // Empty -> Key Path
			},
			expected: TaprootSpendDetails{
				SpendPath: KeyPathSpend,
				Tweak:     merkleRoot,
			},
			err: nil,
		},
		{
			name: "key path spend invalid merkle root length",
			pInput: &psbt.PInput{
				// Invalid length
				TaprootMerkleRoot: []byte{0x01},
			},
			tapDerivation: &psbt.TaprootBip32Derivation{
				XOnlyPubKey: xOnlyPubKey,
				LeafHashes:  nil,
			},
			expected: TaprootSpendDetails{},
			err:      ErrInvalidTaprootMerkleRootLength,
		},
		{
			name: "key path spend already signed",
			pInput: &psbt.PInput{
				// Already signed
				TaprootKeySpendSig: []byte{0x01},
			},
			tapDerivation: &psbt.TaprootBip32Derivation{
				XOnlyPubKey: xOnlyPubKey,
				LeafHashes:  nil,
			},
			expected: TaprootSpendDetails{
				SpendPath: KeyPathSpend,
				Tweak:     nil,
			},
			err: errAlreadySigned,
		},
		{
			name: "script path spend success",
			pInput: &psbt.PInput{
				TaprootLeafScript: tapLeafScriptSuccess,
			},
			tapDerivation: &psbt.TaprootBip32Derivation{
				XOnlyPubKey: xOnlyPubKey,
				LeafHashes:  [][]byte{leafHashCalculated},
			},
			expected: TaprootSpendDetails{
				SpendPath:     ScriptPathSpend,
				WitnessScript: leafScript,
			},
			err: nil,
		},
		{
			name: "script path spend mismatch hash",
			pInput: &psbt.PInput{
				TaprootLeafScript: tapLeafScriptSuccess,
			},
			tapDerivation: &psbt.TaprootBip32Derivation{
				XOnlyPubKey: xOnlyPubKey,
				LeafHashes:  [][]byte{leafHash}, // Mismatch
			},
			expected: TaprootSpendDetails{},
			err:      ErrTaprootLeafHashMismatch,
		},
		{
			name: "script path spend missing script",
			pInput: &psbt.PInput{
				TaprootLeafScript: nil, // Missing
			},
			tapDerivation: &psbt.TaprootBip32Derivation{
				XOnlyPubKey: xOnlyPubKey,
				LeafHashes:  [][]byte{leafHash},
			},
			expected: TaprootSpendDetails{},
			err:      ErrMissingTaprootLeafScript,
		},
		{
			name:   "script path spend multiple leaves unsupported",
			pInput: &psbt.PInput{},
			tapDerivation: &psbt.TaprootBip32Derivation{
				XOnlyPubKey: xOnlyPubKey,
				LeafHashes:  [][]byte{leafHash, leafHash},
			},
			expected: TaprootSpendDetails{},
			err:      ErrUnsupportedTaprootLeafCount,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act: Call createTaprootSpendDetails with the
			// configured input and derivation.
			details, err := createTaprootSpendDetails(
				tc.pInput, tc.tapDerivation,
			)

			// Assert: Verify that the returned spend details match
			// the expected values (SpendPath, Tweak, or
			// WitnessScript) and that any expected errors are
			// returned.
			require.ErrorIs(t, err, tc.err)
			require.Equal(t, tc.expected, details)
		})
	}
}

// TestCreateBip32SpendDetails tests that createBip32SpendDetails correctly
// constructs the SpendDetails required for signing BIP32 inputs, supporting
// various address types.
func TestCreateBip32SpendDetails(t *testing.T) {
	t.Parallel()

	pubKey := bytes.Repeat([]byte{0x02}, 33)
	sig := []byte{0x01}

	tests := []struct {
		name       string
		pInput     *psbt.PInput
		utxo       *wire.TxOut
		addrType   waddrmgr.AddressType
		derivation *psbt.Bip32Derivation
		expected   SpendDetails
		err        error
	}{
		{
			name: "p2wkh success",
			pInput: &psbt.PInput{
				WitnessScript: []byte{0x03},
			},
			utxo:     &wire.TxOut{},
			addrType: waddrmgr.WitnessPubKey,
			derivation: &psbt.Bip32Derivation{
				PubKey: pubKey,
			},
			expected: SegwitV0SpendDetails{
				WitnessScript: []byte{0x03},
			},
			err: nil,
		},
		{
			name:   "p2pkh success",
			pInput: &psbt.PInput{},
			utxo: &wire.TxOut{
				PkScript: []byte{0x04},
			},
			addrType: waddrmgr.PubKeyHash,
			derivation: &psbt.Bip32Derivation{
				PubKey: pubKey,
			},
			expected: LegacySpendDetails{
				RedeemScript: []byte{0x04},
			},
			err: nil,
		},
		{
			name: "nested p2wkh success",
			pInput: &psbt.PInput{
				RedeemScript: []byte{0x05},
			},
			utxo:     &wire.TxOut{},
			addrType: waddrmgr.NestedWitnessPubKey,
			derivation: &psbt.Bip32Derivation{
				PubKey: pubKey,
			},
			expected: SegwitV0SpendDetails{
				WitnessScript: []byte{0x05},
			},
			err: nil,
		},
		{
			name:     "unknown address type",
			pInput:   &psbt.PInput{},
			utxo:     &wire.TxOut{},
			addrType: waddrmgr.Script, // Not supported
			derivation: &psbt.Bip32Derivation{
				PubKey: pubKey,
			},
			expected: nil,
			err:      ErrUnknownAddressType,
		},
		{
			name: "already signed",
			pInput: &psbt.PInput{
				PartialSigs: []*psbt.PartialSig{{
					PubKey:    pubKey,
					Signature: sig,
				}},
			},
			utxo:     &wire.TxOut{},
			addrType: waddrmgr.WitnessPubKey,
			derivation: &psbt.Bip32Derivation{
				PubKey: pubKey,
			},
			expected: nil,
			err:      errAlreadySigned,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act: Call createBip32SpendDetails with the configured
			// input and UTXO information.
			details, err := createBip32SpendDetails(
				tc.pInput, tc.utxo, tc.addrType, tc.derivation,
			)

			// Assert: Verify that the returned spend details
			// correctly reflect the address type (Legacy vs Segwit)
			// and contain the expected scripts, or that an error is
			// returned for invalid states.
			require.ErrorIs(t, err, tc.err)
			require.Equal(t, tc.expected, details)
		})
	}
}

// TestSignTaprootPsbtInput tests that signTaprootPsbtInput successfully
// generates and appends a signature for a valid Taproot input.
func TestSignTaprootPsbtInput(t *testing.T) {
	t.Parallel()

	// Arrange: Setup keys.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	xOnlyPubKey := schnorr.SerializePubKey(pubKey)

	// Arrange: Define the BIP32 derivation path and Taproot derivation
	// information for the input key.
	derivationPath := []uint32{
		hdkeychain.HardenedKeyStart + 86,
		hdkeychain.HardenedKeyStart + 1,
		hdkeychain.HardenedKeyStart + 0,
		0, 0,
	}
	tapDerivation := &psbt.TaprootBip32Derivation{
		XOnlyPubKey: xOnlyPubKey,
		Bip32Path:   derivationPath,
	}

	// Arrange: Create a dummy UTXO with a Taproot script to be signed.
	utxo := &wire.TxOut{
		Value: 1000,
		// Dummy Taproot script
		PkScript: bytes.Repeat([]byte{0x51}, 34),
	}

	// Arrange: Create a PSBT packet containing the transaction with the
	// Taproot input.
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	packet.Inputs[0].WitnessUtxo = utxo
	tapDerivations := []*psbt.TaprootBip32Derivation{tapDerivation}
	packet.Inputs[0].TaprootBip32Derivation = tapDerivations
	packet.Inputs[0].SighashType = txscript.SigHashDefault

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock address lookup flow.
	// 1. FetchScopedKeyManager
	mocks.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(mocks.accountManager, nil)

	// 2. DeriveFromKeyPath (called inside walletdb.View)
	mocks.accountManager.On(
		"DeriveFromKeyPath", mock.Anything, mock.Anything,
	).Return(mocks.pubKeyAddr, nil)

	// 3. Address/PrivKey from ManagedAddress
	mocks.pubKeyAddr.On("PrivKey").Return(privKey, nil)

	// Act: Call signTaprootPsbtInput to sign the input using the mocked
	// wallet and keys.
	sigHashes := txscript.NewTxSigHashes(
		tx, txscript.NewCannedPrevOutputFetcher(
			packet.Inputs[0].WitnessUtxo.PkScript,
			packet.Inputs[0].WitnessUtxo.Value,
		),
	)
	err = w.signTaprootPsbtInput(t.Context(), packet, 0, sigHashes, nil)

	// Assert: Verify that no error occurred and that the TaprootKeySpendSig
	// field in the PSBT input is now populated with a signature.
	require.NoError(t, err)
	require.NotEmpty(t, packet.Inputs[0].TaprootKeySpendSig)
}

// TestSignBip32PsbtInput tests that signBip32PsbtInput successfully generates
// and appends a signature for a valid BIP32 (SegWit v0) input.
func TestSignBip32PsbtInput(t *testing.T) {
	t.Parallel()

	// Arrange: Setup keys.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	pubKeyBytes := pubKey.SerializeCompressed()

	// Arrange: Define the BIP32 derivation path for the input key (BIP-84
	// P2WKH).
	derivationPath := []uint32{
		hdkeychain.HardenedKeyStart + 84,
		hdkeychain.HardenedKeyStart + 1,
		hdkeychain.HardenedKeyStart + 0,
		0, 0,
	}
	derivation := &psbt.Bip32Derivation{
		PubKey:    pubKeyBytes,
		Bip32Path: derivationPath,
	}

	// Arrange: Create a P2WKH UTXO using the public key derived from the
	// path.
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKeyBytes), &chainParams,
	)
	require.NoError(t, err)
	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	utxo := &wire.TxOut{
		Value:    1000,
		PkScript: p2wkhScript,
	}

	// Arrange: Create a PSBT packet containing the transaction with the
	// BIP32 input.
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	packet.Inputs[0].WitnessUtxo = utxo
	packet.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{derivation}
	packet.Inputs[0].SighashType = txscript.SigHashAll
	packet.Inputs[0].WitnessScript = p2wkhScript

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock address lookup flow.
	mocks.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(mocks.accountManager, nil)
	mocks.accountManager.On(
		"DeriveFromKeyPath", mock.Anything, mock.Anything,
	).Return(mocks.pubKeyAddr, nil)
	mocks.pubKeyAddr.On("PrivKey").Return(privKey, nil)

	// Act: Call signBip32PsbtInput to sign the input using the mocked
	// wallet and keys.
	sigHashes := txscript.NewTxSigHashes(
		tx, txscript.NewCannedPrevOutputFetcher(
			packet.Inputs[0].WitnessUtxo.PkScript,
			packet.Inputs[0].WitnessUtxo.Value,
		),
	)
	err = w.signBip32PsbtInput(t.Context(), packet, 0, sigHashes, nil)

	// Assert: Verify that no error occurred and that the PartialSigs field
	// in the PSBT input is populated with a signature from the expected
	// public key.
	require.NoError(t, err)
	require.Len(t, packet.Inputs[0].PartialSigs, 1)
	require.Equal(t, pubKeyBytes, packet.Inputs[0].PartialSigs[0].PubKey)
}

// TestSignPsbtFailNilParams tests that SignPsbt returns ErrNilSignPsbtParams
// when provided with nil parameters.
func TestSignPsbtFailNilParams(t *testing.T) {
	t.Parallel()

	// Arrange: Create a mock wallet.
	w, _ := testWalletWithMocks(t)

	// Act: Call SignPsbt with nil params.
	_, err := w.SignPsbt(t.Context(), nil)

	// Assert: Verify error.
	require.ErrorIs(t, err, ErrNilSignPsbtParams)
}

// TestSignPsbt tests the high-level SignPsbt method, ensuring it correctly
// orchestrates the signing process for a PSBT packet with valid inputs.
func TestSignPsbt(t *testing.T) {
	t.Parallel()

	// Arrange: Setup keys.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	pubKeyBytes := pubKey.SerializeCompressed()

	// Arrange: Define the BIP32 derivation path for the input key
	// (RegressionNet, P2WKH).
	derivationPath := []uint32{
		hdkeychain.HardenedKeyStart + 84,
		// CoinType 1 (RegressionNet)
		hdkeychain.HardenedKeyStart + 1,
		hdkeychain.HardenedKeyStart + 0,
		0, 0,
	}
	derivation := &psbt.Bip32Derivation{
		PubKey:    pubKeyBytes,
		Bip32Path: derivationPath,
	}

	// Arrange: Create a P2WKH UTXO that corresponds to the derivation path,
	// representing the input to be signed.
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKeyBytes), &chainParams,
	)
	require.NoError(t, err)
	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	utxo := &wire.TxOut{
		Value:    1000,
		PkScript: p2wkhScript,
	}

	// Arrange: Create a PSBT packet containing the transaction to be
	// signed.
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{}})
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	packet.Inputs[0].WitnessUtxo = utxo
	packet.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{derivation}
	packet.Inputs[0].SighashType = txscript.SigHashAll

	// Arrange: Wrap the packet in SignPsbtParams.
	signParams := &SignPsbtParams{
		Packet: packet,
	}

	w, mocks := testWalletWithMocks(t)

	// Arrange: Configure mock expectations for key derivation and private
	// key retrieval.
	mocks.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(mocks.accountManager, nil)
	mocks.accountManager.On(
		"DeriveFromKeyPath", mock.Anything, mock.Anything,
	).Return(mocks.pubKeyAddr, nil)
	mocks.pubKeyAddr.On("PrivKey").Return(privKey, nil)

	// Act: Call SignPsbt to perform the full signing workflow on the
	// packet.
	result, err := w.SignPsbt(t.Context(), signParams)

	// Assert: Verify that the operation succeeded, the input is reported as
	// signed, and the underlying PSBT packet contains the generated
	// signature.
	require.NoError(t, err)
	require.Len(t, result.SignedInputs, 1)
	require.Equal(t, uint32(0), result.SignedInputs[0])
	require.Len(t, packet.Inputs[0].PartialSigs, 1)
}

// TestSignPsbtInputsNotReady tests that SignPsbt fails if inputs are not ready
// (missing WitnessUtxo/NonWitnessUtxo).
func TestSignPsbtInputsNotReady(t *testing.T) {
	t.Parallel()

	// Arrange: Packet with input but no UTXO info.
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	signParams := &SignPsbtParams{Packet: packet}
	w, _ := testWalletWithMocks(t)

	// Act.
	_, err = w.SignPsbt(t.Context(), signParams)

	// Assert.
	require.ErrorContains(t, err, "psbt inputs not ready")
}

// TestSignPsbtInvalidDerivationPath tests that SignPsbt returns a fatal error
// if the derivation path is invalid.
func TestSignPsbtInvalidDerivationPath(t *testing.T) {
	t.Parallel()

	// Arrange: Packet with valid UTXO but invalid derivation path.
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{}})
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	packet.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value:    1000,
		PkScript: []byte{0x00, 0x14}, // P2WKH dummy
	}
	// Invalid path (too short).
	packet.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{{
		Bip32Path: []uint32{1, 2, 3},
		PubKey:    make([]byte, 33),
	}}

	signParams := &SignPsbtParams{Packet: packet}
	w, _ := testWalletWithMocks(t)

	// Act.
	_, err = w.SignPsbt(t.Context(), signParams)

	// Assert.
	require.ErrorIs(t, err, ErrInvalidBip32PathLength)
}

// TestSignPsbtSignErrorSkippable tests that SignPsbt skips an input if
// signing fails with a skippable error (e.g. key not found).
func TestSignPsbtSignErrorSkippable(t *testing.T) {
	t.Parallel()

	// Arrange: Packet with valid input.
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{}})
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	p2wkhScript, _ := txscript.PayToAddrScript(
		&btcutil.AddressWitnessPubKeyHash{},
	) // Dummy script
	packet.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value:    1000,
		PkScript: p2wkhScript,
	}
	// Valid path.
	packet.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{{
		Bip32Path: []uint32{
			hdkeychain.HardenedKeyStart + 84,
			hdkeychain.HardenedKeyStart + 1,
			hdkeychain.HardenedKeyStart + 0,
			0, 0,
		},
		PubKey: make([]byte, 33),
	}}
	packet.Inputs[0].SighashType = txscript.SigHashAll

	signParams := &SignPsbtParams{Packet: packet}
	w, mocks := testWalletWithMocks(t)

	// Arrange: Mocks to simulate signing failure.
	mocks.addrStore.On("FetchScopedKeyManager", mock.Anything).
		Return(mocks.accountManager, nil)
	mocks.accountManager.On(
		"DeriveFromKeyPath", mock.Anything, mock.Anything,
	).Return(mocks.pubKeyAddr, nil)

	// PrivKey returns error!
	mocks.pubKeyAddr.On("PrivKey").Return(nil, errKeyNotFound)

	// Act.
	result, err := w.SignPsbt(t.Context(), signParams)

	// Assert: No error, but nothing signed.
	require.NoError(t, err)
	require.Empty(t, result.SignedInputs)
}

// TestSignTaprootPsbtInputErrors tests various error conditions in
// signTaprootPsbtInput.
func TestSignTaprootPsbtInputErrors(t *testing.T) {
	t.Parallel()

	w, _ := testWalletWithMocks(t)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	// Arrange: Add a dummy Witness UTXO to satisfy validity checks.
	packet.Inputs[0].WitnessUtxo = &wire.TxOut{}

	// Case 1: Invalid Derivation Path.
	tapDerivation := []*psbt.TaprootBip32Derivation{{
		Bip32Path: []uint32{1}, // Too short
	}}
	packet.Inputs[0].TaprootBip32Derivation = tapDerivation
	err = w.signTaprootPsbtInput(t.Context(), packet, 0, nil, nil)
	require.ErrorIs(t, err, ErrInvalidBip32PathLength)

	// Case 2: CreateTaprootSpendDetails error (e.g. invalid merkle root).
	packet.Inputs[0].TaprootBip32Derivation[0].Bip32Path = []uint32{
		hdkeychain.HardenedKeyStart + 86,
		hdkeychain.HardenedKeyStart + 1,
		hdkeychain.HardenedKeyStart + 0,
		0, 0,
	}
	packet.Inputs[0].TaprootMerkleRoot = []byte{0x01} // Invalid length
	err = w.signTaprootPsbtInput(t.Context(), packet, 0, nil, nil)
	require.ErrorIs(t, err, ErrInvalidTaprootMerkleRootLength)
}

// TestSignBip32PsbtInputErrors tests various error conditions in
// signBip32PsbtInput.
func TestSignBip32PsbtInputErrors(t *testing.T) {
	t.Parallel()

	w, _ := testWalletWithMocks(t)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	// Arrange: Add a dummy Witness UTXO to satisfy validity checks.
	packet.Inputs[0].WitnessUtxo = &wire.TxOut{}

	// Case 1: Invalid Derivation Path.
	packet.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{{
		Bip32Path: []uint32{1}, // Too short
	}}
	err = w.signBip32PsbtInput(t.Context(), packet, 0, nil, nil)
	require.ErrorIs(t, err, ErrInvalidBip32PathLength)
}

// TestAddScriptToPInput tests that addScriptToPInput correctly updates
// the PSBT input with the provided witness and/or sigScript.
func TestAddScriptToPInput(t *testing.T) {
	t.Parallel()

	// Arrange: Dummy witness and sigScript.
	witness := wire.TxWitness{[]byte{0x01}, []byte{0x02}}
	sigScript := []byte{0x03}

	// Arrange: Expected serialized witness:
	// - 0x02 (stack items)
	// - 0x01 (len) + 0x01 (data)
	// - 0x01 (len) + 0x02 (data)
	expectedWitness := []byte{0x02, 0x01, 0x01, 0x01, 0x02}

	tests := []struct {
		name            string
		witness         wire.TxWitness
		sigScript       []byte
		expectedWitness []byte
		expectedSig     []byte
	}{
		{
			name:            "witness only",
			witness:         witness,
			sigScript:       nil,
			expectedWitness: expectedWitness,
			expectedSig:     nil,
		},
		{
			name:            "sigScript only",
			witness:         nil,
			sigScript:       sigScript,
			expectedWitness: nil,
			expectedSig:     sigScript,
		},
		{
			name:            "both",
			witness:         witness,
			sigScript:       sigScript,
			expectedWitness: expectedWitness,
			expectedSig:     sigScript,
		},
		{
			name:            "none",
			witness:         nil,
			sigScript:       nil,
			expectedWitness: nil,
			expectedSig:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: UnlockingScript and target PInput.
			script := &UnlockingScript{
				Witness:   tc.witness,
				SigScript: tc.sigScript,
			}
			pInput := &psbt.PInput{}

			// Act: Call addScriptToPInput.
			err := addScriptToPInput(pInput, script)

			// Assert: Verify no error and fields match
			// expectations.
			require.NoError(t, err)
			require.Equal(t, tc.expectedWitness,
				pInput.FinalScriptWitness)
			require.Equal(t, tc.expectedSig,
				pInput.FinalScriptSig)
		})
	}
}

// TestFinalizeInput tests that finalizeInput correctly processes a single PSBT
// input, handling success, skips, and errors.
func TestFinalizeInput(t *testing.T) {
	t.Parallel()

	// Arrange: Setup keys.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)
	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		// Arrange: Valid PSBT input.
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{})
		packet, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)

		packet.Inputs[0].WitnessUtxo = &wire.TxOut{
			Value:    1000,
			PkScript: p2wkhScript,
		}
		packet.Inputs[0].SighashType = txscript.SigHashAll

		w, mocks := testWalletWithMocks(t)

		// Arrange: Mock dependencies.
		mocks.addrStore.On(
			"Address", mock.Anything, mock.Anything,
		).Return(mocks.pubKeyAddr, nil)
		mocks.pubKeyAddr.On("AddrType").Return(waddrmgr.WitnessPubKey)
		mocks.pubKeyAddr.On("PrivKey").Return(privKey, nil)

		sigHashes := txscript.NewTxSigHashes(
			tx, txscript.NewCannedPrevOutputFetcher(
				packet.Inputs[0].WitnessUtxo.PkScript,
				packet.Inputs[0].WitnessUtxo.Value,
			),
		)

		// Act.
		err = w.finalizeInput(t.Context(), packet, 0, sigHashes)

		// Assert.
		require.NoError(t, err)
		require.NotEmpty(t, packet.Inputs[0].FinalScriptWitness)
	})

	t.Run("skip finalized", func(t *testing.T) {
		t.Parallel()
		// Arrange: Already finalized input.
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{})
		packet, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)

		packet.Inputs[0].FinalScriptWitness = []byte{0x01}

		w, _ := testWalletWithMocks(t)

		// Act.
		err = w.finalizeInput(t.Context(), packet, 0, nil)

		// Assert: No error, remains unchanged (mock not called).
		require.NoError(t, err)
	})

	t.Run("skip missing utxo", func(t *testing.T) {
		t.Parallel()
		// Arrange: Input without UTXO.
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{})
		packet, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)

		w, _ := testWalletWithMocks(t)

		// Act.
		err = w.finalizeInput(t.Context(), packet, 0, nil)

		// Assert: No error (logs error but continues).
		require.NoError(t, err)
	})

	t.Run("skip malformed script", func(t *testing.T) {
		t.Parallel()
		// Arrange: Input with malformed pkScript.
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{})
		packet, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)

		// OP_RETURN script cannot be extracted as an address.
		packet.Inputs[0].WitnessUtxo = &wire.TxOut{
			Value:    1000,
			PkScript: []byte{0x6a},
		}

		w, _ := testWalletWithMocks(t)

		// Act.
		err = w.finalizeInput(t.Context(), packet, 0, nil)

		// Assert: No error (logs error but continues).
		require.NoError(t, err)
	})
}

// TestFinalizePsbtSuccess tests that FinalizePsbt successfully generates
// witnesses for supported input types (P2WKH, Taproot).
func TestFinalizePsbtSuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Setup keys.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	// Arrange: Create addresses/scripts.
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)
	p2wkhScript, err := txscript.PayToAddrScript(p2wkhAddr)
	require.NoError(t, err)

	trAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(pubKey), &chainParams,
	)
	require.NoError(t, err)
	trScript, err := txscript.PayToAddrScript(trAddr)
	require.NoError(t, err)

	tests := []struct {
		name     string
		pkScript []byte
		addrType waddrmgr.AddressType
		addr     btcutil.Address
	}{
		{
			name:     "p2wkh",
			pkScript: p2wkhScript,
			addrType: waddrmgr.WitnessPubKey,
			addr:     p2wkhAddr,
		},
		{
			name:     "taproot",
			pkScript: trScript,
			addrType: waddrmgr.TaprootPubKey,
			addr:     trAddr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Create PSBT.
			tx := wire.NewMsgTx(2)
			tx.AddTxIn(&wire.TxIn{})
			tx.AddTxOut(&wire.TxOut{Value: 1000}) // Add output
			packet, err := psbt.NewFromUnsignedTx(tx)
			require.NoError(t, err)

			packet.Inputs[0].WitnessUtxo = &wire.TxOut{
				Value:    1000,
				PkScript: tc.pkScript,
			}
			packet.Inputs[0].SighashType = txscript.SigHashDefault

			w, mocks := testWalletWithMocks(t)

			// Arrange: Mock address lookup.
			mocks.addrStore.On(
				"Address", mock.Anything,
				mock.MatchedBy(func(a btcutil.Address) bool {
					return a.String() == tc.addr.String()
				}),
			).Return(mocks.pubKeyAddr, nil)

			// Arrange: Mock ManagedPubKeyAddress.
			// Note: Address() and PubKey() are not called for
			// P2WKH/Taproot signing paths in
			// ComputeUnlockingScript.
			mocks.pubKeyAddr.On("AddrType").Return(tc.addrType)

			// Create a copy of the private key to avoid data races
			// when parallel tests call Zero() on it.
			privKeyCopy := *privKey
			mocks.pubKeyAddr.On("PrivKey").Return(&privKeyCopy, nil)

			// Act: Call FinalizePsbt.
			err = w.FinalizePsbt(t.Context(), packet)

			// Assert: Verify success and witness presence.
			require.NoError(t, err)
			require.NotEmpty(
				t, packet.Inputs[0].FinalScriptWitness,
			)
		})
	}
}

// TestFinalizePsbtErrors tests error conditions for FinalizePsbt.
func TestFinalizePsbtErrors(t *testing.T) {
	t.Parallel()

	t.Run("inputs not ready", func(t *testing.T) {
		t.Parallel()
		// Arrange: Packet with input but no UTXO info.
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{})
		tx.AddTxOut(&wire.TxOut{Value: 1000})
		packet, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)

		w, _ := testWalletWithMocks(t)

		// Act.
		err = w.FinalizePsbt(t.Context(), packet)

		// Assert.
		require.ErrorContains(t, err, "psbt inputs not ready")
	})

	t.Run("finalization failed", func(t *testing.T) {
		t.Parallel()
		// Arrange: Packet with valid UTXO but we can't sign it (watch
		// only).
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{})
		tx.AddTxOut(&wire.TxOut{Value: 1000})
		packet, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)

		// Use a valid P2WKH script so extraction succeeds.
		p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
			make([]byte, 20), &chainParams,
		)
		require.NoError(t, err)
		dummyScript, err := txscript.PayToAddrScript(p2wkhAddr)
		require.NoError(t, err)

		packet.Inputs[0].WitnessUtxo = &wire.TxOut{
			Value:    1000,
			PkScript: dummyScript,
		}

		w, mocks := testWalletWithMocks(t)

		// Arrange: Mock Address lookup to return error (or watch only).
		// Simulating "Address not found" or "Key not found".
		// ComputeUnlockingScript will fail, log, and continue.
		// Then MaybeFinalizeAll will fail because no witness.
		mocks.addrStore.On("Address", mock.Anything, mock.Anything).
			Return(nil, errAddrNotFound)

		// Act.
		err = w.FinalizePsbt(t.Context(), packet)

		// Assert: Should return error from MaybeFinalizeAll.
		require.ErrorContains(t, err, "error finalizing PSBT")
	})
}

// TestValidatePsbtMerge tests the validatePsbtMerge helper function.
func TestValidatePsbtMerge(t *testing.T) {
	t.Parallel()

	// Helper to create a dummy packet with specific tx hash and IO counts.
	createPacket := func(txHash byte, inCount, outCount int) *psbt.Packet {
		tx := wire.NewMsgTx(2)
		// Add dummy inputs/outputs to affect count and hash.
		for i := range inCount {
			tx.AddTxIn(&wire.TxIn{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{txHash},
					Index: uint32(i),
				},
			})
		}

		for i := range outCount {
			tx.AddTxOut(&wire.TxOut{Value: int64(i)})
		}

		p, _ := psbt.NewFromUnsignedTx(tx)

		return p
	}

	base := createPacket(1, 1, 1)

	tests := []struct {
		name    string
		psbts   []*psbt.Packet
		wantErr error
	}{
		{
			name:    "success single",
			psbts:   []*psbt.Packet{base},
			wantErr: nil,
		},
		{
			name:    "success multiple identical",
			psbts:   []*psbt.Packet{base, base},
			wantErr: nil,
		},
		{
			name:    "empty list",
			psbts:   []*psbt.Packet{},
			wantErr: ErrNoPsbtsToCombine,
		},
		{
			name:    "mismatched txid",
			psbts:   []*psbt.Packet{base, createPacket(2, 1, 1)},
			wantErr: ErrDifferentTransactions,
		},
		{
			name: "mismatched input count",
			psbts: func() []*psbt.Packet {
				// Create a packet with same TXID but corrupted
				// input count.
				p2 := createPacket(1, 1, 1)
				p2.Inputs = append(p2.Inputs, psbt.PInput{})

				return []*psbt.Packet{base, p2}
			}(),
			wantErr: ErrInputCountMismatch,
		},
		{
			name: "mismatched output count",
			psbts: func() []*psbt.Packet {
				// Create a packet with same TXID but corrupted
				// output count.
				p2 := createPacket(1, 1, 1)
				p2.Outputs = append(p2.Outputs, psbt.POutput{})

				return []*psbt.Packet{base, p2}
			}(),
			wantErr: ErrOutputCountMismatch,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := validatePsbtMerge(tc.psbts)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, got)
			} else {
				require.NoError(t, err)
				require.NotNil(t, got)

				// Verify it is a different object (copy).
				require.NotSame(t, tc.psbts[0], got)

				// Verify structure matches base.
				require.Equal(t,
					tc.psbts[0].UnsignedTx.TxHash(),
					got.UnsignedTx.TxHash(),
				)
				require.Len(t, got.Inputs,
					len(tc.psbts[0].Inputs))
				require.Len(t, got.Outputs,
					len(tc.psbts[0].Outputs))
			}
		})
	}
}

// TestMergePsbtInputs tests that mergePsbtInputs correctly merges and
// deduplicates input fields.
func TestMergePsbtInputs(t *testing.T) {
	t.Parallel()

	t.Run("partial sigs deduplication", func(t *testing.T) {
		t.Parallel()

		// Arrange: Create a destination input with one signature, and
		// a source input with the same signature (duplicate) plus a
		// new one. This simulates merging updates from multiple
		// signers where some data overlaps.
		dest := &psbt.PInput{
			PartialSigs: []*psbt.PartialSig{
				{
					PubKey:    []byte{1},
					Signature: []byte{10},
				},
			},
		}
		src := &psbt.PInput{
			PartialSigs: []*psbt.PartialSig{
				{
					PubKey:    []byte{1},
					Signature: []byte{10},
				}, // Duplicate
				{
					PubKey:    []byte{2},
					Signature: []byte{20},
				}, // New
			},
		}

		// Act: Merge the source input into the destination.
		err := mergePsbtInputs(dest, src)
		require.NoError(t, err)

		// Assert: Verify that the destination now contains exactly two
		// signatures. The first one should be preserved, and the
		// second one should be the new signature from the source.
		require.Len(t, dest.PartialSigs, 2)
		require.Equal(t, []byte{1}, dest.PartialSigs[0].PubKey)
		require.Equal(t, []byte{2}, dest.PartialSigs[1].PubKey)
	})

	t.Run("sighash type adoption", func(t *testing.T) {
		t.Parallel()

		// Arrange: Create a destination input with the default sighash
		// type (0) and a source input with a specific type
		// (SigHashSingle).
		dest := &psbt.PInput{SighashType: 0} // Default
		src := &psbt.PInput{SighashType: txscript.SigHashSingle}

		// Act: Merge the inputs.
		err := mergePsbtInputs(dest, src)

		// Assert: Verify that the destination adopted the source's
		// sighash type, as 0 is treated as "unset".
		require.NoError(t, err)
		require.Equal(t, txscript.SigHashSingle, dest.SighashType)

		// Arrange: Create a scenario with conflicting sighash types.
		// Destination has SigHashAll, Source has SigHashSingle.
		dest.SighashType = txscript.SigHashAll
		src.SighashType = txscript.SigHashSingle

		// Act: Attempt to merge conflicting inputs.
		err = mergePsbtInputs(dest, src)

		// Assert: Verify that the merge returns an error indicating
		// the mismatch.
		require.ErrorContains(t, err, "sighash type mismatch")
	})

	t.Run("scripts merging", func(t *testing.T) {
		t.Parallel()

		// Arrange: Create a destination input missing script info, and
		// a source input containing it.
		dest := &psbt.PInput{}
		src := &psbt.PInput{
			RedeemScript:  []byte{1, 2, 3},
			WitnessScript: []byte{4, 5, 6},
		}

		// Act: Merge the inputs.
		err := mergePsbtInputs(dest, src)

		// Assert: Verify that the scripts were successfully copied to
		// the destination.
		require.NoError(t, err)
		require.Equal(t, src.RedeemScript, dest.RedeemScript)
		require.Equal(t, src.WitnessScript, dest.WitnessScript)
	})
}

// TestMergePsbtOutputs tests that mergePsbtOutputs correctly merges and
// deduplicates output fields.
func TestMergePsbtOutputs(t *testing.T) {
	t.Parallel()

	t.Run("bip32 derivation deduplication", func(t *testing.T) {
		t.Parallel()

		// Arrange: Create destination and source outputs with
		// overlapping BIP32 derivation paths.
		dest := &psbt.POutput{
			Bip32Derivation: []*psbt.Bip32Derivation{
				{
					PubKey:               []byte{1},
					MasterKeyFingerprint: 10,
				},
			},
		}
		src := &psbt.POutput{
			Bip32Derivation: []*psbt.Bip32Derivation{
				{
					PubKey:               []byte{1},
					MasterKeyFingerprint: 10,
				}, // Duplicate
				{
					PubKey:               []byte{2},
					MasterKeyFingerprint: 20,
				}, // New
			},
		}

		// Act: Merge the outputs.
		err := mergePsbtOutputs(dest, src)
		require.NoError(t, err)

		// Assert: Verify that the destination now contains both unique
		// derivations.
		require.Len(t, dest.Bip32Derivation, 2)
		require.Equal(t, []byte{1}, dest.Bip32Derivation[0].PubKey)
		require.Equal(t, []byte{2}, dest.Bip32Derivation[1].PubKey)
	})

	t.Run("taproot internal key adoption", func(t *testing.T) {
		t.Parallel()

		// Arrange: Create a destination output missing the Taproot
		// internal key, and a source output that has it.
		dest := &psbt.POutput{}
		src := &psbt.POutput{
			TaprootInternalKey: []byte{1, 2, 3},
		}

		// Act: Merge the outputs.
		err := mergePsbtOutputs(dest, src)

		require.NoError(t, err)
		require.Equal(t, src.TaprootInternalKey,
			dest.TaprootInternalKey)
	})
}

// TestAddInputInfoSegWitV0 tests the legacy helper for adding SegWit v0 input
// info.
func TestAddInputInfoSegWitV0(t *testing.T) {
	t.Parallel()

	// Arrange: Setup input parameters (prevTx, utxo, derivation).
	in := &psbt.PInput{}
	prevTx := wire.NewMsgTx(1)
	utxo := &wire.TxOut{Value: 1000, PkScript: []byte{1}}
	derivation := &psbt.Bip32Derivation{PubKey: []byte{2}}
	witnessProgram := []byte{3}

	// Mock address type.
	mockAddr := &mockManagedAddress{}
	mockAddr.On("AddrType").Return(waddrmgr.NestedWitnessPubKey)

	// Act: Call the helper.
	addInputInfoSegWitV0(in, prevTx, utxo, derivation, mockAddr,
		witnessProgram)

	// Assert: Verify fields are populated correctly.
	require.Equal(t, prevTx, in.NonWitnessUtxo)
	require.Equal(t, utxo.Value, in.WitnessUtxo.Value)
	require.Equal(t, utxo.PkScript, in.WitnessUtxo.PkScript)
	require.Equal(t, txscript.SigHashAll, in.SighashType)
	require.Equal(t, derivation, in.Bip32Derivation[0])
	require.Equal(t, witnessProgram, in.RedeemScript)
}

// TestAddInputInfoSegWitV1 tests the legacy helper for adding SegWit v1 input
// info.
func TestAddInputInfoSegWitV1(t *testing.T) {
	t.Parallel()

	// Arrange: Setup input parameters.
	in := &psbt.PInput{}
	utxo := &wire.TxOut{Value: 1000, PkScript: []byte{1}}
	// PubKey must be valid length for slicing [1:].
	pubKey := make([]byte, 33)
	pubKey[0] = 0x02
	derivation := &psbt.Bip32Derivation{PubKey: pubKey}

	// Act: Call the helper.
	addInputInfoSegWitV1(in, utxo, derivation)

	// Assert: Verify fields are populated correctly.
	require.Equal(t, utxo.Value, in.WitnessUtxo.Value)
	require.Equal(t, txscript.SigHashDefault, in.SighashType)
	require.Equal(t, derivation, in.Bip32Derivation[0])
	require.Equal(t, pubKey[1:], in.TaprootBip32Derivation[0].XOnlyPubKey)
}

// TestPsbtPrevOutputFetcher tests that the prev output fetcher correctly
// retrieves UTXOs from the PSBT packet.
func TestPsbtPrevOutputFetcher(t *testing.T) {
	t.Parallel()

	// Arrange: Create a PSBT packet with multiple inputs.
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 0}})
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 1}})

	packet, _ := psbt.NewFromUnsignedTx(tx)

	// Input 0: NonWitnessUtxo.
	prevTx := wire.NewMsgTx(1)
	prevTx.AddTxOut(&wire.TxOut{Value: 1000})
	packet.Inputs[0].NonWitnessUtxo = prevTx

	// Input 1: WitnessUtxo.
	packet.Inputs[1].WitnessUtxo = &wire.TxOut{Value: 2000}

	// Act: Create the fetcher.
	fetcher := PsbtPrevOutputFetcher(packet)

	// Assert: Check input 0 (NonWitness).
	out0 := fetcher.FetchPrevOutput(wire.OutPoint{Index: 0})
	require.NotNil(t, out0)
	require.Equal(t, int64(1000), out0.Value)

	// Assert: Check input 1 (Witness).
	out1 := fetcher.FetchPrevOutput(wire.OutPoint{Index: 1})
	require.NotNil(t, out1)
	require.Equal(t, int64(2000), out1.Value)
}

// TestMergeSighashType tests the mergeSighashType helper function.
//
// It verifies two key behaviors:
//  1. Conflict Detection: It ensures that an error is returned if the
//     destination and source inputs have different, non-zero sighash types.
//  2. Adoption: It ensures that if the destination has a default (0) sighash
//     type, it correctly adopts the type from the source.
func TestMergeSighashType(t *testing.T) {
	t.Parallel()

	t.Run("detect mismatch", func(t *testing.T) {
		t.Parallel()

		// Arrange: Construct a 'destination' PSBT input that has
		// already declared a sighash type of SigHashAll.
		dest := &psbt.PInput{SighashType: txscript.SigHashAll}

		// Arrange: Construct a 'source' PSBT input that declares a
		// different, conflicting sighash type of SigHashSingle.
		src := &psbt.PInput{SighashType: txscript.SigHashSingle}

		// Act: Attempt to merge the source into the destination using
		// the mergeSighashType helper.
		err := mergeSighashType(dest, src)

		// Assert: Verify that the function identified the conflict and
		// returned the expected ErrSighashMismatch error.
		require.ErrorIs(t, err, ErrSighashMismatch)
	})

	t.Run("adopt source type", func(t *testing.T) {
		t.Parallel()

		// Arrange: Construct a 'destination' PSBT input with the
		// default (zero) sighash type, indicating it hasn't been set
		// yet.
		dest := &psbt.PInput{SighashType: 0}

		// Arrange: Construct a 'source' PSBT input with a specific
		// sighash type (SigHashSingle) that should be propagated.
		src := &psbt.PInput{SighashType: txscript.SigHashSingle}

		// Act: Merge the source into the destination.
		err := mergeSighashType(dest, src)

		// Assert: Verify that the operation was successful (no error)
		// and that the destination input has been updated to match the
		// source's sighash type.
		require.NoError(t, err)
		require.Equal(t, txscript.SigHashSingle, dest.SighashType)
	})
}

// TestMergeRedeemScript tests the mergeRedeemScript helper function.
//
// It verifies that:
// 1. Conflicting redeem scripts cause an error.
// 2. A missing redeem script in the destination is populated from the source.
func TestMergeRedeemScript(t *testing.T) {
	t.Parallel()

	t.Run("detect mismatch", func(t *testing.T) {
		t.Parallel()

		// Arrange: Create a 'destination' input with a specific redeem
		// script (byte sequence {1}).
		dest := &psbt.PInput{RedeemScript: []byte{1}}

		// Arrange: Create a 'source' input with a different redeem
		// script (byte sequence {2}).
		src := &psbt.PInput{RedeemScript: []byte{2}}

		// Act: Attempt to merge the source into the destination.
		err := mergeRedeemScript(dest, src)

		// Assert: Verify that the function returns
		// ErrRedeemScriptMismatch, preventing the corruption of the
		// redeem script.
		require.ErrorIs(t, err, ErrRedeemScriptMismatch)
	})

	t.Run("adopt source script", func(t *testing.T) {
		t.Parallel()

		// Arrange: Create a 'destination' input with no redeem script
		// (nil or empty).
		dest := &psbt.PInput{}

		// Arrange: Create a 'source' input that contains a valid
		// redeem script.
		src := &psbt.PInput{RedeemScript: []byte{1, 2, 3}}

		// Act: Merge the source into the destination.
		err := mergeRedeemScript(dest, src)

		// Assert: Verify that the merge succeeded and the destination
		// now contains the redeem script from the source.
		require.NoError(t, err)
		require.Equal(t, src.RedeemScript, dest.RedeemScript)
	})
}

// TestMergeWitnessUtxo tests the mergeWitnessUtxo helper function.
//
// It verifies that:
//  1. Conflicting Witness UTXO values (amount or script) trigger an error.
//  2. A missing Witness UTXO in the destination is correctly copied from the
//     source.
func TestMergeWitnessUtxo(t *testing.T) {
	t.Parallel()

	t.Run("detect value mismatch", func(t *testing.T) {
		t.Parallel()

		// Arrange: Create a 'destination' input with a Witness UTXO
		// valued at 1000 sats.
		dest := &psbt.PInput{WitnessUtxo: &wire.TxOut{Value: 1000}}

		// Arrange: Create a 'source' input with a Witness UTXO valued
		// at 2000 sats (conflicting).
		src := &psbt.PInput{WitnessUtxo: &wire.TxOut{Value: 2000}}

		// Act: Attempt to merge the inputs.
		err := mergeWitnessUtxo(dest, src)

		// Assert: Verify that the function returns
		// ErrWitnessUtxoMismatch.
		require.ErrorIs(t, err, ErrWitnessUtxoMismatch)
	})

	t.Run("detect script mismatch", func(t *testing.T) {
		t.Parallel()

		// Arrange: Create a 'destination' input with a Witness UTXO
		// script {1}.
		dest := &psbt.PInput{
			WitnessUtxo: &wire.TxOut{
				Value: 1000, PkScript: []byte{1},
			},
		}

		// Arrange: Create a 'source' input with the same value but a
		// different script {2}.
		src := &psbt.PInput{
			WitnessUtxo: &wire.TxOut{
				Value: 1000, PkScript: []byte{2},
			},
		}

		// Act: Attempt to merge the inputs.
		err := mergeWitnessUtxo(dest, src)

		// Assert: Verify that the function returns
		// ErrWitnessUtxoMismatch due to the script difference.
		require.ErrorIs(t, err, ErrWitnessUtxoMismatch)
	})

	t.Run("adopt source utxo", func(t *testing.T) {
		t.Parallel()

		// Arrange: Create a 'destination' input with no Witness UTXO
		// info.
		dest := &psbt.PInput{}

		// Arrange: Create a 'source' input with a full Witness UTXO.
		src := &psbt.PInput{
			WitnessUtxo: &wire.TxOut{
				Value: 1000, PkScript: []byte{1},
			},
		}

		// Act: Merge the source into the destination.
		err := mergeWitnessUtxo(dest, src)

		// Assert: Verify that the destination structure now holds the
		// exact Witness UTXO pointer/value from the source.
		require.NoError(t, err)
		require.Equal(t, src.WitnessUtxo, dest.WitnessUtxo)
	})
}

// TestMergeNonWitnessUtxo tests the mergeNonWitnessUtxo helper function.
//
// It ensures that full transaction data (for legacy/SegWit v0 inputs) is
// merged safely, rejecting conflicts where the transaction hash differs.
func TestMergeNonWitnessUtxo(t *testing.T) {
	t.Parallel()

	t.Run("detect mismatch", func(t *testing.T) {
		t.Parallel()

		// Arrange: Create two distinct wire transactions to serve as
		// conflicting NonWitnessUtxo data.
		tx1 := wire.NewMsgTx(1)
		tx2 := wire.NewMsgTx(2)

		// Arrange: Assign tx1 to destination and tx2 to source.
		dest := &psbt.PInput{NonWitnessUtxo: tx1}
		src := &psbt.PInput{NonWitnessUtxo: tx2}

		// Act: Attempt to merge.
		err := mergeNonWitnessUtxo(dest, src)

		// Assert: Verify that ErrNonWitnessUtxoMismatch is returned
		// because the transactions differ.
		require.ErrorIs(t, err, ErrNonWitnessUtxoMismatch)
	})

	t.Run("adopt source utxo", func(t *testing.T) {
		t.Parallel()

		// Arrange: Create a 'destination' input with no
		// NonWitnessUtxo.
		dest := &psbt.PInput{}

		// Arrange: Create a 'source' input with a valid NonWitnessUtxo
		// transaction.
		tx := wire.NewMsgTx(1)
		src := &psbt.PInput{NonWitnessUtxo: tx}

		// Act: Merge the inputs.
		err := mergeNonWitnessUtxo(dest, src)

		// Assert: Verify that the destination adopted the
		// NonWitnessUtxo from the source.
		require.NoError(t, err)
		require.Equal(t, src.NonWitnessUtxo, dest.NonWitnessUtxo)
	})
}

// TestMergeTaprootInternalKeyMismatch verifies that conflicting Taproot
// internal keys are detected.
func TestMergeTaprootInternalKeyMismatch(t *testing.T) {
	t.Parallel()

	// Arrange: Setup conflicting Taproot internal keys (byte {1} vs
	// byte {2}).
	dest := &psbt.POutput{TaprootInternalKey: []byte{1}}
	src := &psbt.POutput{TaprootInternalKey: []byte{2}}

	// Act: Attempt to merge the outputs.
	err := mergeTaprootInternalKey(dest, src)

	// Assert: Verify that ErrTaprootInternalKeyMismatch is returned.
	require.ErrorIs(t, err, ErrTaprootInternalKeyMismatch)
}

// TestMergeTaprootInternalKeyAdoption verifies that a source key is adopted
// if the destination key is missing.
func TestMergeTaprootInternalKeyAdoption(t *testing.T) {
	t.Parallel()

	// Arrange: Create a destination output with no internal key.
	dest := &psbt.POutput{}

	// Arrange: Create a source output with a valid internal key.
	src := &psbt.POutput{TaprootInternalKey: []byte{1, 2, 3}}

	// Act: Merge the outputs.
	err := mergeTaprootInternalKey(dest, src)

	// Assert: Verify that the internal key was successfully copied to
	// the destination.
	require.NoError(t, err)
	require.Equal(t, src.TaprootInternalKey, dest.TaprootInternalKey)
}

// TestDeduplicateTaprootBip32Derivations tests the deduplication logic for
// Taproot BIP32 derivations.
func TestDeduplicateTaprootBip32Derivations(t *testing.T) {
	t.Parallel()

	t.Run("deduplicate", func(t *testing.T) {
		t.Parallel()

		// Arrange: Setup destination with one derivation.
		dest := []*psbt.TaprootBip32Derivation{
			{XOnlyPubKey: []byte{1}},
		}

		// Arrange: Setup source with duplicate and new derivation.
		src := []*psbt.TaprootBip32Derivation{
			{XOnlyPubKey: []byte{1}}, // Duplicate
			{XOnlyPubKey: []byte{2}}, // New
		}

		// Act.
		got := deduplicateTaprootBip32Derivations(dest, src)

		// Assert: Verify deduplication.
		require.Len(t, got, 2)
		require.Equal(t, []byte{1}, got[0].XOnlyPubKey)
		require.Equal(t, []byte{2}, got[1].XOnlyPubKey)
	})
}

// TestMergeInputScripts tests the aggregate mergeInputScripts function to
// ensure it propagates errors from all sub-steps.
func TestMergeInputScripts(t *testing.T) {
	t.Parallel()

	t.Run("fail on redeem script", func(t *testing.T) {
		t.Parallel()

		dest := &psbt.PInput{RedeemScript: []byte{1}}
		src := &psbt.PInput{RedeemScript: []byte{2}}
		err := mergeInputScripts(dest, src)
		require.ErrorIs(t, err, ErrRedeemScriptMismatch)
	})

	t.Run("fail on witness script", func(t *testing.T) {
		t.Parallel()

		dest := &psbt.PInput{WitnessScript: []byte{1}}
		src := &psbt.PInput{WitnessScript: []byte{2}}
		err := mergeInputScripts(dest, src)
		require.ErrorIs(t, err, ErrWitnessScriptMismatch)
	})

	t.Run("fail on final script sig", func(t *testing.T) {
		t.Parallel()

		dest := &psbt.PInput{FinalScriptSig: []byte{1}}
		src := &psbt.PInput{FinalScriptSig: []byte{2}}
		err := mergeInputScripts(dest, src)
		require.ErrorIs(t, err, ErrFinalScriptSigMismatch)
	})

	t.Run("fail on final script witness", func(t *testing.T) {
		t.Parallel()

		dest := &psbt.PInput{FinalScriptWitness: []byte{1}}
		src := &psbt.PInput{FinalScriptWitness: []byte{2}}
		err := mergeInputScripts(dest, src)
		require.ErrorIs(t, err, ErrFinalScriptWitnessMismatch)
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		dest := &psbt.PInput{}
		src := &psbt.PInput{
			RedeemScript:       []byte{1},
			WitnessScript:      []byte{2},
			FinalScriptSig:     []byte{3},
			FinalScriptWitness: []byte{4},
		}
		err := mergeInputScripts(dest, src)
		require.NoError(t, err)
		require.Equal(t, src.RedeemScript, dest.RedeemScript)
		require.Equal(t, src.WitnessScript, dest.WitnessScript)
		require.Equal(t, src.FinalScriptSig, dest.FinalScriptSig)
		require.Equal(t, src.FinalScriptWitness,
			dest.FinalScriptWitness)
	})
}

// TestMergeOutputScripts tests the aggregate mergeOutputScripts function.
func TestMergeOutputScripts(t *testing.T) {
	t.Parallel()

	t.Run("fail on redeem script", func(t *testing.T) {
		t.Parallel()

		dest := &psbt.POutput{RedeemScript: []byte{1}}
		src := &psbt.POutput{RedeemScript: []byte{2}}
		err := mergeOutputScripts(dest, src)
		require.ErrorIs(t, err, ErrRedeemScriptMismatch)
	})

	t.Run("fail on witness script", func(t *testing.T) {
		t.Parallel()

		dest := &psbt.POutput{WitnessScript: []byte{1}}
		src := &psbt.POutput{WitnessScript: []byte{2}}
		err := mergeOutputScripts(dest, src)
		require.ErrorIs(t, err, ErrWitnessScriptMismatch)
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		dest := &psbt.POutput{}
		src := &psbt.POutput{
			RedeemScript:  []byte{1},
			WitnessScript: []byte{2},
		}
		err := mergeOutputScripts(dest, src)
		require.NoError(t, err)
		require.Equal(t, src.RedeemScript, dest.RedeemScript)
		require.Equal(t, src.WitnessScript, dest.WitnessScript)
	})
}

// TestCombinePsbt tests that CombinePsbt correctly merges multiple PSBTs.
func TestCombinePsbt(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		w, _ := testWalletWithMocks(t)

		// Arrange: Create a base transaction with 1 input and 1 output.
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{})
		tx.AddTxOut(&wire.TxOut{Value: 1000}) // Add output

		// Arrange: Create two PSBT packets from this transaction.
		packet1, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)

		packet2, err := psbt.NewFromUnsignedTx(tx)
		require.NoError(t, err)

		// Arrange: Add UTXO info to satisfy structural validation
		// checks.
		dummyUtxo := &wire.TxOut{Value: 1000, PkScript: []byte{0x00}}
		packet1.Inputs[0].WitnessUtxo = dummyUtxo
		packet2.Inputs[0].WitnessUtxo = dummyUtxo

		// Arrange: Add a unique partial signature to the second
		// packet.
		packet2.Inputs[0].PartialSigs = []*psbt.PartialSig{{
			PubKey: []byte{1}, Signature: []byte{1},
		}}

		// Act: Combine the two packets.
		combined, err := w.CombinePsbt(t.Context(), packet1, packet2)

		// Assert: Verify the merge was successful and the resulting
		// packet contains the signature from packet2.
		require.NoError(t, err)
		require.Len(t, combined.Inputs[0].PartialSigs, 1)
		require.Equal(t, []byte{1},
			combined.Inputs[0].PartialSigs[0].PubKey)
	})

	t.Run("empty inputs", func(t *testing.T) {
		t.Parallel()
		w, _ := testWalletWithMocks(t)

		// Act: Attempt to combine with no packets.
		_, err := w.CombinePsbt(t.Context())

		// Assert: Verify it returns the expected error.
		require.ErrorIs(t, err, ErrNoPsbtsToCombine)
	})

	t.Run("mismatch tx", func(t *testing.T) {
		t.Parallel()
		w, _ := testWalletWithMocks(t)

		// Arrange: Create two packets with DIFFERENT transactions.
		tx1 := wire.NewMsgTx(2)
		tx1.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash: chainhash.Hash{1},
			},
		})
		packet1, err := psbt.NewFromUnsignedTx(tx1)
		require.NoError(t, err)

		tx2 := wire.NewMsgTx(2)
		tx2.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash: chainhash.Hash{2},
			},
		})
		packet2, err := psbt.NewFromUnsignedTx(tx2)
		require.NoError(t, err)

		// Act: Attempt to combine conflicting packets.
		_, err = w.CombinePsbt(t.Context(), packet1, packet2)

		// Assert: Verify it returns the specific mismatch error.
		require.ErrorIs(t, err, ErrDifferentTransactions)
	})
}
