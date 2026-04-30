// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcwallet/pkg/btcunit"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestBuildTxDetailFromStore tests the detailed store-backed tx builder.
func TestBuildTxDetailFromStore(t *testing.T) {
	t.Parallel()

	// Create the various test cases.
	minedDetails, minedTxDetail := createMinedTxDetail(t)
	unminedDetails, unminedTxDetail := createUnminedTxDetail(t)
	unminedNoFeeDetails, unminedNoFeeTxDetail := createUnminedTxDetail(t)
	unminedNoFeeDetails.Debits = nil
	unminedNoFeeTxDetail.Fee = 0
	unminedNoFeeTxDetail.FeeRate = btcunit.ZeroSatPerVByte
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
			w, _ := createStartedWalletWithMocks(t)
			currentHeight := int32(1)

			// Act: Build the TxDetail.
			result, err := w.buildTxDetailFromStore(
				txDetailInfoFromLegacy(tc.details), currentHeight,
			)

			// Assert: Check that the correct details are returned.
			require.NoError(t, err)
			require.Equal(t, tc.expectedTxDetail, result)
		})
	}
}

// TestBuildTxDetailFromStoreRequiresMsgTx tests that store rows must include a
// parsed transaction.
func TestBuildTxDetailFromStoreRequiresMsgTx(t *testing.T) {
	t.Parallel()

	// Arrange: Create a store detail row that violates the MsgTx contract.
	minedDetails, _ := createMinedTxDetail(t)
	txDetails := txDetailInfoFromLegacy(minedDetails)
	txDetails.MsgTx = nil
	w, _ := createStartedWalletWithMocks(t)

	// Act: Build the TxDetail from the malformed store row.
	_, err := w.buildTxDetailFromStore(txDetails, 1)

	// Assert: Check that the contract violation is reported.
	require.ErrorIs(t, err, errNilTxDetailMsgTx)
}

// TestGetTxPropagatesNilMsgTx tests that GetTx returns store detail contract
// violations to callers.
func TestGetTxPropagatesNilMsgTx(t *testing.T) {
	t.Parallel()

	// Arrange: Mock a store detail row that omits the parsed transaction.
	minedDetails, _ := createMinedTxDetail(t)
	txDetails := txDetailInfoFromLegacy(minedDetails)
	txDetails.MsgTx = nil
	w, mocks := createStartedWalletWithMocks(t)
	mocks.store.On("GetTxDetail", mock.Anything, db.GetTxDetailQuery{
		WalletID: w.id,
		Txid:     *TstTxHash,
	}).Return(txDetails, nil).Once()

	// Act: Get the transaction through the public wallet method.
	_, err := w.GetTx(t.Context(), *TstTxHash)

	// Assert: Check that the contract violation is propagated.
	require.ErrorIs(t, err, errNilTxDetailMsgTx)
}

// TestGetTxSuccess tests the GetTx method of the wallet for success scenarios.
func TestGetTxSuccess(t *testing.T) {
	t.Parallel()

	minedDetails, minedTxDetail := createMinedTxDetail(t)
	unminedDetails, unminedTxDetail := createUnminedTxDetail(t)

	testCases := []struct {
		name             string
		mockDetails      *db.TxDetailInfo
		expectedTxDetail *TxDetail
	}{
		{
			name:             "mined tx",
			mockDetails:      txDetailInfoFromLegacy(minedDetails),
			expectedTxDetail: minedTxDetail,
		},
		{
			name:             "unmined tx",
			mockDetails:      txDetailInfoFromLegacy(unminedDetails),
			expectedTxDetail: unminedTxDetail,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Arrange: Create a test wallet with mocks.
			w, mocks := createStartedWalletWithMocks(t)
			// SyncedTo is mocked in createStartedWalletWithMocks (height 1).

			mocks.store.On("GetTxDetail", mock.Anything, db.GetTxDetailQuery{
				WalletID: w.id,
				Txid:     *TstTxHash,
			}).Return(tc.mockDetails, nil).Once()

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

	// Arrange: Create a test wallet with mocks and mock the detail read to
	// return ErrTxNotFound, simulating a non-existing tx.
	w, mocks := createStartedWalletWithMocks(t)
	mocks.store.On("GetTxDetail", mock.Anything, db.GetTxDetailQuery{
		WalletID: w.id,
		Txid:     *TstTxHash,
	}).Return(nil, db.ErrTxNotFound).Once()

	// Act: Attempt to get the transaction.
	_, err := w.GetTx(t.Context(), *TstTxHash)

	// Assert that the correct error is returned.
	require.ErrorIs(t, err, ErrTxNotFound)
}

// TestListTxnsSuccess tests the ListTxns method of the wallet.
func TestListTxnsSuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet with mocks and a mock tx record.
	w, mocks := createStartedWalletWithMocks(t)
	_, expectedTxDetail := createMinedTxDetail(t)

	// SyncedTo is mocked in createStartedWalletWithMocks (height 1).

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
	weight := btcunit.NewWeightUnit(uint64(blockchain.GetTransactionWeight(
		btcutil.NewTx(&rec.MsgTx),
	)))
	unminedTxDetail := &TxDetail{
		Hash:          *TstTxHash,
		RawTx:         TstSerializedTx,
		Label:         testLabel,
		Value:         totalCredits - debitAmt,
		Fee:           fee,
		FeeRate:       btcunit.CalcSatPerVByte(fee, weight.ToVB()),
		Confirmations: 0,
		Weight:        weight,
		ReceivedTime:  txTime,
		Outputs:       expectedOutputs,
		PrevOuts:      expectedPrevOuts,
	}

	return unminedDetails, unminedTxDetail
}

// createMinedTxDetail builds on createUnminedTxDetail to create a mined
// transaction. The transaction has one confirmation.
func createMinedTxDetail(t *testing.T) (*wtxmgr.TxDetails, *TxDetail) {
	t.Helper()

	minedDetails, minedTxDetail := createUnminedTxDetail(t)
	// Set height to 1 to match the default SyncedTo mock (height 1).
	minedDetails.Block.Height = 1
	minedDetails.Block.Time = time.Unix(1616161617, 0)
	minedTxDetail.Confirmations = 1
	minedTxDetail.Block = &BlockDetails{
		Height:    1,
		Timestamp: minedDetails.Block.Time.Unix(),
	}

	return minedDetails, minedTxDetail
}

// txDetailInfoFromLegacy converts one legacy wtxmgr transaction fixture into
// the db-native detail shape consumed by store-backed reader tests.
func txDetailInfoFromLegacy(details *wtxmgr.TxDetails) *db.TxDetailInfo {
	var block *db.Block
	if details.Block.Height >= 0 {
		block = &db.Block{
			Hash:      details.Block.Hash,
			Height:    uint32(details.Block.Height),
			Timestamp: details.Block.Time,
		}
	}

	ownedInputs := make([]db.TxOwnedInput, 0, len(details.Debits))
	for _, debit := range details.Debits {
		ownedInputs = append(ownedInputs, db.TxOwnedInput{
			Index:  debit.Index,
			Amount: debit.Amount,
		})
	}

	ownedOutputs := make([]db.TxOwnedOutput, 0, len(details.Credits))
	for _, credit := range details.Credits {
		ownedOutputs = append(ownedOutputs, db.TxOwnedOutput{
			Index:  credit.Index,
			Amount: credit.Amount,
		})
	}

	return &db.TxDetailInfo{
		Hash:         details.Hash,
		MsgTx:        &details.MsgTx,
		SerializedTx: details.SerializedTx,
		Received:     details.Received,
		Block:        block,
		Status:       db.TxStatusPublished,
		Label:        details.Label,
		OwnedInputs:  ownedInputs,
		OwnedOutputs: ownedOutputs,
	}
}
