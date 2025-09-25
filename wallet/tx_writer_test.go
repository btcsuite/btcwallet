// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"testing"

	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestLabelTxSuccess tests that we can successfully label a transaction.
func TestLabelTxSuccess(t *testing.T) {
	t.Parallel()

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock the TxDetails call to simulate a known transaction.
	// We return a non-nil TxDetails to pass the check.
	mocks.txStore.On("TxDetails", mock.Anything, TstTxHash).
		Return(&wtxmgr.TxDetails{}, nil).Once()

	// Arrange: Mock the PutTxLabel call. We expect it to be called with
	// the new label.
	newLabel := "new label"
	mocks.txStore.On("PutTxLabel", mock.Anything, *TstTxHash, newLabel).
		Return(nil).Once()

	// Act: Call the LabelTx function.
	err := w.LabelTx(t.Context(), *TstTxHash, newLabel)

	// Assert: Check that there was no error and that the mocks were called
	// as expected.
	require.NoError(t, err)
	mocks.txStore.AssertExpectations(t)
}

// TestLabelTxNotFound tests that we get an error when we try to label a tx
// that is not known to the wallet.
func TestLabelTxNotFound(t *testing.T) {
	t.Parallel()

	w, mocks := testWalletWithMocks(t)

	// Arrange: Mock the TxDetails call to return nil, simulating a tx
	// that is not known to the wallet.
	mocks.txStore.On("TxDetails", mock.Anything, TstTxHash).
		Return(nil, nil).Once()

	// Act: Attempt to label a tx that is not known to the wallet.
	err := w.LabelTx(t.Context(), *TstTxHash, "some label")

	// Assert: Check that the correct error is returned.
	require.ErrorIs(t, err, ErrTxNotFound)
	mocks.txStore.AssertExpectations(t)
}
