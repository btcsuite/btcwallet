// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"strings"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestLabelTxSuccess tests that we can successfully label a transaction.
func TestLabelTxSuccess(t *testing.T) {
	t.Parallel()

	w, mocks := createStartedWalletWithMocks(t)

	newLabel := "new label"
	mocks.store.On("UpdateTx", mock.Anything, db.UpdateTxParams{
		WalletID: w.id,
		Txid:     *TstTxHash,
		Label:    &newLabel,
	}).Return(nil).Once()

	// Act: Call the LabelTx function.
	err := w.LabelTx(t.Context(), *TstTxHash, newLabel)

	// Assert: Check that there was no error and that the mocks were called
	// as expected.
	require.NoError(t, err)
	mocks.store.AssertExpectations(t)
}

// TestLabelTxEmptyLabel tests that an empty label is forwarded to the store and
// preserves the legacy label error.
func TestLabelTxEmptyLabel(t *testing.T) {
	t.Parallel()

	w, mocks := createStartedWalletWithMocks(t)

	empty := ""
	mocks.store.On("UpdateTx", mock.Anything, db.UpdateTxParams{
		WalletID: w.id,
		Txid:     *TstTxHash,
		Label:    &empty,
	}).Return(wtxmgr.ErrEmptyLabel).Once()

	err := w.LabelTx(t.Context(), *TstTxHash, empty)

	require.ErrorIs(t, err, wtxmgr.ErrEmptyLabel)
	mocks.store.AssertExpectations(t)
}

// TestLabelTxAtLimit tests that a label of exactly the maximum length reaches
// the store, so the limit rejects only what lies past it.
func TestLabelTxAtLimit(t *testing.T) {
	t.Parallel()

	w, mocks := createStartedWalletWithMocks(t)

	longest := strings.Repeat("x", MaxTxLabelLength)
	mocks.store.On("UpdateTx", mock.Anything, db.UpdateTxParams{
		WalletID: w.id,
		Txid:     *TstTxHash,
		Label:    &longest,
	}).Return(nil).Once()

	err := w.LabelTx(t.Context(), *TstTxHash, longest)

	require.NoError(t, err)
	mocks.store.AssertExpectations(t)
}

// TestLabelTxTooLong tests that a label past the maximum length is rejected
// with the wallet's own error before any store sees it. The store is left
// without expectations on purpose: reaching it at all is the failure.
func TestLabelTxTooLong(t *testing.T) {
	t.Parallel()

	w, mocks := createStartedWalletWithMocks(t)

	err := w.LabelTx(
		t.Context(), *TstTxHash, strings.Repeat("x", MaxTxLabelLength+1),
	)

	require.ErrorIs(t, err, ErrLabelTooLong)
	mocks.store.AssertExpectations(t)
}

// TestLabelTxMultiByteTooLong tests that the limit counts bytes rather than
// characters. A label of three-byte runes can sit well inside a character
// limit and past a byte limit at once, which is the case where the stores
// disagree: the SQL schemas would keep it and the legacy kvdb store would
// refuse it, so the wallet settles which one it is.
func TestLabelTxMultiByteTooLong(t *testing.T) {
	t.Parallel()

	w, mocks := createStartedWalletWithMocks(t)

	// Three bytes per rune, so one rune more than a third of the limit is
	// the shortest label that is inside it in characters and past it in
	// bytes.
	label := strings.Repeat("€", MaxTxLabelLength/3+1)
	require.Greater(t, len(label), MaxTxLabelLength)
	require.Less(t, len([]rune(label)), MaxTxLabelLength)

	err := w.LabelTx(t.Context(), *TstTxHash, label)

	require.ErrorIs(t, err, ErrLabelTooLong)
	mocks.store.AssertExpectations(t)
}

// TestLabelTxNotFound tests that we get an error when we try to label a tx
// that is not known to the wallet.
func TestLabelTxNotFound(t *testing.T) {
	t.Parallel()

	w, mocks := createStartedWalletWithMocks(t)

	label := "some label"
	mocks.store.On("UpdateTx", mock.Anything, db.UpdateTxParams{
		WalletID: w.id,
		Txid:     *TstTxHash,
		Label:    &label,
	}).Return(db.ErrTxNotFound).Once()

	// Act: Attempt to label a tx that is not known to the wallet.
	err := w.LabelTx(t.Context(), *TstTxHash, label)

	// Assert: Check that the correct error is returned.
	require.ErrorIs(t, err, ErrTxNotFound)
	mocks.store.AssertExpectations(t)
}
