// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
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
