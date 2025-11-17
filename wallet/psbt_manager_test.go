// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var errDb = errors.New("db error")

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
	p2wkhAddr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()), &chainParams,
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
		mock.MatchedBy(func(addr address.Address) bool {
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
	taprootAddr, err := address.NewAddressTaproot(
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
		mock.MatchedBy(func(addr address.Address) bool {
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

	p2wkhAddr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()), &chainParams,
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

	p2wkhAddr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()), &chainParams,
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

	p2wkhAddr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()), &chainParams,
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

	p2wkhAddr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()), &chainParams,
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

	p2wkhAddr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()), &chainParams,
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
		mock.MatchedBy(func(addr address.Address) bool {
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

	p2wkhAddr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()), &chainParams,
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
