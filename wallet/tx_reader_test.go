// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/pkg/unit"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestBuildTxDetail tests the buildTxDetail function.
func TestBuildTxDetail(t *testing.T) {
	t.Parallel()

	// Create the various test cases.
	minedDetails, minedTxDetail := createMinedTxDetail(t)
	unminedDetails, unminedTxDetail := createUnminedTxDetail(t)
	unminedNoFeeDetails, unminedNoFeeTxDetail := createUnminedTxDetail(t)
	unminedNoFeeDetails.Debits = nil
	unminedNoFeeTxDetail.Fee = 0
	unminedNoFeeTxDetail.FeeRate = 0
	unminedNoFeeTxDetail.Value = unminedNoFeeDetails.Credits[0].Amount +
		unminedNoFeeDetails.Credits[1].Amount
	unminedNoFeeTxDetail.PrevOuts[0].IsOurs = false

	testCases := []struct {
		name             string
		details          *wtxmgr.TxDetails
		expectedTxDetail *TxDetail
	}{
		{
			name:             "mined tx",
			details:          minedDetails,
			expectedTxDetail: minedTxDetail,
		},
		{
			name:             "unmined tx",
			details:          unminedDetails,
			expectedTxDetail: unminedTxDetail,
		},
		{
			name:             "unmined tx no fee",
			details:          unminedNoFeeDetails,
			expectedTxDetail: unminedNoFeeTxDetail,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Arrange: Create a test wallet with mocks.
			w, _ := testWalletWithMocks(t)
			currentHeight := int32(100)

			// Act: Build the TxDetail.
			result := w.buildTxDetail(tc.details, currentHeight)

			// Assert: Check that the correct details are returned.
			require.Equal(t, tc.expectedTxDetail, result)
		})
	}
}

// TestGetTxSuccess tests the GetTx method of the wallet for success scenarios.
func TestGetTxSuccess(t *testing.T) {
	t.Parallel()

	minedDetails, minedTxDetail := createMinedTxDetail(t)
	unminedDetails, unminedTxDetail := createUnminedTxDetail(t)

	testCases := []struct {
		name             string
		mockDetails      *wtxmgr.TxDetails
		expectedTxDetail *TxDetail
	}{
		{
			name:             "mined tx",
			mockDetails:      minedDetails,
			expectedTxDetail: minedTxDetail,
		},
		{
			name:             "unmined tx",
			mockDetails:      unminedDetails,
			expectedTxDetail: unminedTxDetail,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Arrange: Create a test wallet with mocks.
			w, mocks := testWalletWithMocks(t)
			mocks.addrStore.On("SyncedTo").Return(
				waddrmgr.BlockStamp{
					Height: 100,
				},
			)
			mocks.txStore.On("TxDetails", mock.Anything, TstTxHash).
				Return(tc.mockDetails, nil).Once()

			// Act: Get the transaction.
			details, err := w.GetTx(t.Context(), *TstTxHash)

			// Assert: Check that the correct details are returned.
			require.NoError(t, err)
			require.Equal(t, tc.expectedTxDetail, details)
		})
	}
}

// TestGetTxNotFound tests that GetTx returns the correct error when a
// transaction is not found.
func TestGetTxNotFound(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet with mocks and mock the TxDetails call
	// to return nil, simulating a non-existing tx.
	w, mocks := testWalletWithMocks(t)
	mocks.txStore.On("TxDetails", mock.Anything, TstTxHash).
		Return(nil, nil).Once()

	// Act: Attempt to get the transaction.
	_, err := w.GetTx(t.Context(), *TstTxHash)

	// Assert that the correct error is returned.
	require.ErrorIs(t, err, ErrTxNotFound)
}

// TestListTxnsSuccess tests the ListTxns method of the wallet.
func TestListTxnsSuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet with mocks and a mock tx record.
	w, mocks := testWalletWithMocks(t)
	_, expectedTxDetail := createMinedTxDetail(t)

	mocks.addrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{
		Height: 100,
	})

	// Set up the mock for the tx store. We use .Run to execute the
	// callback function that's passed in as an argument to the mock.
	mocks.txStore.On("RangeTransactions",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Run(func(args mock.Arguments) {
		// Get the callback function from the arguments.
		f, ok := args.Get(3).(func([]wtxmgr.TxDetails) (bool, error))
		require.True(t, ok)

		// Create the mock details to pass to the callback.
		minedDetails, _ := createMinedTxDetail(t)
		details := []wtxmgr.TxDetails{*minedDetails}

		// Call the callback.
		_, err := f(details)
		require.NoError(t, err)
	}).Return(nil).Once()

	// Act: List txns.
	details, err := w.ListTxns(t.Context(), 0, 1000)

	// Assert: Check that the correct details are returned.
	require.NoError(t, err)
	require.Len(t, details, 1)
	require.Equal(t, expectedTxDetail, details[0])
}

// createUnminedTxDetail creates a test transaction that sends funds from the
// wallet to two of its own addresses. The transaction is unmined and has no
// confirmations.
//
// The transaction details are as follows:
//   - The transaction has one input, which is owned by the wallet.
//   - The transaction has two outputs, both of which are owned by the wallet.
//   - The total value of the outputs (totalCredits) is the sum of the two
//     output amounts.
//   - The total value of the inputs (debitAmt) is the sum of the credits plus
//     a fee.
//   - The net value of the transaction from the wallet's perspective (Value) is
//     totalCredits - debitAmt, which is equal to -fee.
func createUnminedTxDetail(t *testing.T) (*wtxmgr.TxDetails, *TxDetail) {
	t.Helper()

	// Create a deterministic timestamp for the test tx record.
	txTime := time.Unix(1616161616, 0)
	rec, err := wtxmgr.NewTxRecord(TstSerializedTx, txTime)
	require.NoError(t, err)

	// Deserialize the test transaction to avoid using a global variable.
	tx, err := btcutil.NewTxFromBytes(TstSerializedTx)
	require.NoError(t, err)

	msgTx := tx.MsgTx()

	// The credits are the sum of all outputs of the test tx.
	var totalCredits btcutil.Amount
	for _, txOut := range msgTx.TxOut {
		totalCredits += btcutil.Amount(txOut.Value)
	}

	// The debit amount is the total credit amount plus a fee.
	fee := btcutil.Amount(1000)
	debitAmt := totalCredits + fee
	testLabel := "test"

	out0Amt := btcutil.Amount(msgTx.TxOut[0].Value)
	out1Amt := btcutil.Amount(msgTx.TxOut[1].Value)

	// Create a fully populated TxDetail for the unmined case.
	unminedDetails := &wtxmgr.TxDetails{
		TxRecord: *rec,
		Block: wtxmgr.BlockMeta{
			Block: wtxmgr.Block{
				Height: -1,
			},
		},
		Credits: []wtxmgr.CreditRecord{
			{
				Index:  0,
				Amount: out0Amt,
			},
			{
				Index:  1,
				Amount: out1Amt,
			},
		},
		Debits: []wtxmgr.DebitRecord{
			{
				Index:  0,
				Amount: debitAmt,
			},
		},
		Label: testLabel,
	}

	// Manually build the expected outputs for the test tx.
	expectedOutputs := make([]Output, len(msgTx.TxOut))
	for i, txOut := range msgTx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			txOut.PkScript, &chaincfg.RegressionNetParams,
		)
		require.NoError(t, err)

		expectedOutputs[i] = Output{
			Type:      2,
			Addresses: addrs,
			PkScript:  txOut.PkScript,
			Index:     i,
			Amount:    btcutil.Amount(txOut.Value),
			IsOurs:    true,
		}
	}

	// Manually build the expected previous outputs for the test tx.
	expectedPrevOuts := []PrevOut{
		{
			OutPoint: msgTx.TxIn[0].PreviousOutPoint,
			IsOurs:   true,
		},
	}

	// Define the expected TxDetail for the unmined case.
	unminedTxDetail := &TxDetail{
		Hash:          *TstTxHash,
		RawTx:         TstSerializedTx,
		Label:         testLabel,
		Value:         totalCredits - debitAmt,
		Fee:           fee,
		FeeRate:       4,
		Confirmations: 0,
		Weight: unit.WeightUnit(blockchain.GetTransactionWeight(
			btcutil.NewTx(&rec.MsgTx),
		)),
		ReceivedTime: txTime,
		Outputs:      expectedOutputs,
		PrevOuts:     expectedPrevOuts,
	}

	return unminedDetails, unminedTxDetail
}

// createMinedTxDetail builds on createUnminedTxDetail to create a mined
// transaction. The transaction has one confirmation.
func createMinedTxDetail(t *testing.T) (*wtxmgr.TxDetails, *TxDetail) {
	t.Helper()

	minedDetails, minedTxDetail := createUnminedTxDetail(t)
	minedDetails.Block.Height = 100
	minedDetails.Block.Time = time.Unix(1616161617, 0)
	minedTxDetail.Confirmations = 1
	minedTxDetail.Block = &BlockDetails{
		Height:    100,
		Timestamp: minedDetails.Block.Time.Unix(),
	}

	return minedDetails, minedTxDetail
}
