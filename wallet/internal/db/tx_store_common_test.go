package db

import (
	"bytes"
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestSerializeDeserializeMsgTx verifies that the common serialization helpers
// preserve transaction bytes across a round trip.
func TestSerializeDeserializeMsgTx(t *testing.T) {
	t.Parallel()

	// Arrange: Build one regular transaction fixture.
	tx := testRegularMsgTx()

	// Act: Serialize it and deserialize the result.
	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	decoded, err := deserializeMsgTx(rawTx)
	require.NoError(t, err)

	var got bytes.Buffer

	err = decoded.Serialize(&got)
	require.NoError(t, err)

	// Assert: The decoded transaction serializes back to the same bytes.
	require.Equal(t, rawTx, got.Bytes())
}

// TestReverseTxInfosByBlockPreservesBlockLocalOrder verifies that reversing a
// summary range reverses block groups without reversing transactions inside the
// same block.
func TestReverseTxInfosByBlockPreservesBlockLocalOrder(t *testing.T) {
	t.Parallel()

	// Arrange: Build confirmed summaries ordered by ascending block height and
	// block-local transaction order.
	infos := []TxInfo{
		{Hash: chainhash.Hash{1}, Block: testBlock(1)},
		{Hash: chainhash.Hash{2}, Block: testBlock(1)},
		{Hash: chainhash.Hash{3}, Block: testBlock(2)},
		{Hash: chainhash.Hash{4}, Block: testBlock(3)},
		{Hash: chainhash.Hash{5}, Block: testBlock(3)},
	}

	// Act: Reverse the summaries by block group.
	ReverseTxInfosByBlock(infos)

	// Assert: Block order is reversed, while each block's local tx order is
	// preserved.
	require.Equal(t, chainhash.Hash{4}, infos[0].Hash)
	require.Equal(t, chainhash.Hash{5}, infos[1].Hash)
	require.Equal(t, chainhash.Hash{3}, infos[2].Hash)
	require.Equal(t, chainhash.Hash{1}, infos[3].Hash)
	require.Equal(t, chainhash.Hash{2}, infos[4].Hash)
}

// TestReverseTxDetailBasesByBlockPreservesBlockLocalOrder verifies that
// reversing detail base rows preserves transaction order inside each block.
func TestReverseTxDetailBasesByBlockPreservesBlockLocalOrder(t *testing.T) {
	t.Parallel()

	// Arrange: Build confirmed detail bases ordered by ascending block
	// height and block-local transaction order.
	bases := []TxDetailBase{
		{ID: 1, Block: testBlock(1)},
		{ID: 2, Block: testBlock(1)},
		{ID: 3, Block: testBlock(2)},
		{ID: 4, Block: testBlock(3)},
		{ID: 5, Block: testBlock(3)},
	}

	// Act: Reverse the base rows by block group.
	ReverseTxDetailBasesByBlock(bases)

	// Assert: Block order is reversed, while each block's local tx order is
	// preserved.
	require.Equal(t, int64(4), bases[0].ID)
	require.Equal(t, int64(5), bases[1].ID)
	require.Equal(t, int64(3), bases[2].ID)
	require.Equal(t, int64(1), bases[3].ID)
	require.Equal(t, int64(2), bases[4].ID)
}

// TestGetTxDetailWithOpsSuccess verifies that the shared GetTxDetail workflow
// loads the base row first, then the owned edges, before rebuilding the final
// detail shape.
func TestGetTxDetailWithOpsSuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Build one detail query, one normalized base row,
	// and one mock ops adapter that records the shared call order.
	tx := testRegularMsgTxWithSeed(11)
	base := testTxDetailBase(t, 41, tx, testBlock(144), TxStatusPublished,
		"detail-label")
	query := GetTxDetailQuery{WalletID: 7, Txid: tx.TxHash()}
	wantInputOutpoints := []TxInputOutpoint{testInputOutpoint(41, tx)}

	var callOrder []string

	baseHash := query.Txid
	ops := &mockGetTxDetailOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("LoadBase", mock.Anything, query).Return(base, nil).Run(
		func(mock.Arguments) {
			callOrder = append(callOrder, "base")
		},
	).Once()

	ops.On("LoadOwnedOutputs", mock.Anything, uint32(7), []int64{41}).Return(
		map[int64][]TxOwnedOutput{41: {{Index: 1, Amount: 12}}}, nil,
	).Run(func(mock.Arguments) {
		callOrder = append(callOrder, "outputs")
	}).Once()

	ops.On(
		"LoadOwnedInputs", mock.Anything, uint32(7), wantInputOutpoints,
	).Return(
		map[int64][]TxOwnedInput{41: {{Index: 0, Amount: 21}}}, nil,
	).Run(func(mock.Arguments) {
		callOrder = append(callOrder, "inputs")
	}).Once()

	// Act: Run the shared detail workflow.
	detail, err := GetTxDetailWithOps(context.Background(), query, ops)

	// Assert: The helper preserves the staged ordering and rebuilds the final
	// detail shape from the normalized base row plus owned edges.
	require.NoError(t, err)
	require.Equal(t, []string{"base", "outputs", "inputs"}, callOrder)
	require.Equal(t, baseHash, detail.Hash)
	require.Equal(t, "detail-label", detail.Label)
	require.Equal(t, time.UTC, detail.Received.Location())
	require.NotNil(t, detail.MsgTx)
	require.Len(t, detail.OwnedInputs, 1)
	require.Len(t, detail.OwnedOutputs, 1)
	require.NotNil(t, detail.Block)
	require.Equal(t, uint32(144), detail.Block.Height)
}

// TestGetTxDetailWithOpsLoadOutputsError verifies that the shared GetTxDetail
// helper stops after an owned-output load failure and wraps that error with the
// workflow stage context.
func TestGetTxDetailWithOpsLoadOutputsError(t *testing.T) {
	t.Parallel()

	// Arrange: Return one valid base row and one owned-output load failure.
	tx := testRegularMsgTxWithSeed(12)
	query := GetTxDetailQuery{WalletID: 8, Txid: tx.TxHash()}
	base := testTxDetailBase(t, 55, tx, nil, TxStatusPending, "")
	ops := &mockGetTxDetailOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("LoadBase", mock.Anything, query).Return(base, nil).Once()
	ops.On("LoadOwnedOutputs", mock.Anything, uint32(8), []int64{55}).Return(
		nil, errCreateTxTest,
	).Once()

	// Act: Run the shared detail workflow.
	_, err := GetTxDetailWithOps(context.Background(), query, ops)

	// Assert: The helper reports the stage-local error and does not
	// continue on to the later input load.
	require.ErrorIs(t, err, errCreateTxTest)
	require.ErrorContains(t, err, "load tx detail outputs")
}

// TestListTxDetailsWithOpsUnminedFirst verifies that the shared ListTxDetails
// workflow prepends unmined rows when the wallet tx-reader range starts at the
// unmined leg.
func TestListTxDetailsWithOpsUnminedFirst(t *testing.T) {
	t.Parallel()

	// Arrange: Build one unmined row, one confirmed row, and one
	// mock ops adapter that records both call order and the final
	// tx-id batch.
	unminedTx := testRegularMsgTxWithSeed(21)
	confirmedTx := testRegularMsgTxWithSeed(22)
	query := ListTxDetailsQuery{WalletID: 9, StartHeight: -1, EndHeight: 100}
	wantInputOutpoints := []TxInputOutpoint{
		testInputOutpoint(71, unminedTx),
		testInputOutpoint(72, confirmedTx),
	}

	var (
		callOrder  []string
		batchedIDs []int64
	)

	ops := &mockListTxDetailsOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("ListUnmined", mock.Anything, uint32(9)).Return(
		[]TxDetailBase{
			testTxDetailBase(t, 71, unminedTx, nil, TxStatusPending, "u"),
		}, nil,
	).Run(func(mock.Arguments) {
		callOrder = append(callOrder, "unmined")
	}).Once()

	ops.On("ListConfirmed", mock.Anything, uint32(9), int32(100),
		int32(math.MaxInt32), true).Return(
		[]TxDetailBase{
			testTxDetailBase(
				t, 72, confirmedTx, testBlock(100), TxStatusPublished, "c",
			),
		}, nil,
	).Run(func(mock.Arguments) {
		callOrder = append(callOrder, "confirmed")
	}).Once()

	ops.On(
		"LoadOwnedOutputs", mock.Anything, uint32(9), []int64{71, 72},
	).Return(
		map[int64][]TxOwnedOutput{
			71: {{Index: 0, Amount: 7}},
			72: {{Index: 0, Amount: 8}},
		}, nil,
	).Run(func(args mock.Arguments) {
		callOrder = append(callOrder, "outputs")
		ids, ok := args.Get(2).([]int64)
		require.True(t, ok)
		batchedIDs = append([]int64(nil), ids...)
	}).Once()

	ops.On(
		"LoadOwnedInputs", mock.Anything, uint32(9), wantInputOutpoints,
	).Return(
		map[int64][]TxOwnedInput{
			71: {{Index: 0, Amount: 3}},
			72: {{Index: 0, Amount: 4}},
		}, nil,
	).Run(func(mock.Arguments) {
		callOrder = append(callOrder, "inputs")
	}).Once()

	// Act: Run the shared list-detail workflow.
	details, err := ListTxDetailsWithOps(context.Background(), query, ops)

	// Assert: The helper preserves the unmined-first ordering and batches owned
	// edge loads using that final tx-id order.
	require.NoError(t, err)
	require.Equal(t,
		[]string{"unmined", "confirmed", "outputs", "inputs"}, callOrder,
	)
	require.Equal(t, []int64{71, 72}, batchedIDs)
	require.Len(t, details, 2)
	require.Equal(t, unminedTx.TxHash(), details[0].Hash)
	require.Equal(t, confirmedTx.TxHash(), details[1].Hash)
	require.Nil(t, details[0].Block)
	require.NotNil(t, details[1].Block)
}

// TestListTxDetailsWithOpsUnminedLast verifies that the shared ListTxDetails
// workflow appends unmined rows when the wallet tx-reader range ends at the
// unmined leg.
func TestListTxDetailsWithOpsUnminedLast(t *testing.T) {
	t.Parallel()

	// Arrange: Build one confirmed row, one unmined row, and one mock adapter
	// that records the workflow ordering.
	confirmedTx := testRegularMsgTxWithSeed(31)
	unminedTx := testRegularMsgTxWithSeed(32)
	query := ListTxDetailsQuery{WalletID: 10, StartHeight: 5, EndHeight: -1}
	wantInputOutpoints := []TxInputOutpoint{
		testInputOutpoint(81, confirmedTx),
		testInputOutpoint(82, unminedTx),
	}

	var callOrder []string

	ops := &mockListTxDetailsOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("ListConfirmed", mock.Anything, uint32(10), int32(5),
		int32(math.MaxInt32), false).Return(
		[]TxDetailBase{
			testTxDetailBase(
				t, 81, confirmedTx, testBlock(5), TxStatusPublished, "c",
			),
		}, nil,
	).Run(func(mock.Arguments) {
		callOrder = append(callOrder, "confirmed")
	}).Once()

	ops.On("ListUnmined", mock.Anything, uint32(10)).Return(
		[]TxDetailBase{
			testTxDetailBase(t, 82, unminedTx, nil, TxStatusPending, "u"),
		}, nil,
	).Run(func(mock.Arguments) {
		callOrder = append(callOrder, "unmined")
	}).Once()

	ops.On(
		"LoadOwnedOutputs", mock.Anything, uint32(10), []int64{81, 82},
	).Return(
		map[int64][]TxOwnedOutput{
			81: {{Index: 0, Amount: 5}},
			82: {{Index: 0, Amount: 6}},
		}, nil,
	).Run(func(mock.Arguments) {
		callOrder = append(callOrder, "outputs")
	}).Once()

	ops.On(
		"LoadOwnedInputs", mock.Anything, uint32(10), wantInputOutpoints,
	).Return(
		map[int64][]TxOwnedInput{
			81: {{Index: 0, Amount: 2}},
			82: {{Index: 0, Amount: 1}},
		}, nil,
	).Run(func(mock.Arguments) {
		callOrder = append(callOrder, "inputs")
	}).Once()

	// Act: Run the shared list-detail workflow.
	details, err := ListTxDetailsWithOps(context.Background(), query, ops)

	// Assert: The helper keeps the confirmed rows first and appends the unmined
	// rows before loading owned edges.
	require.NoError(t, err)
	require.Equal(t,
		[]string{"confirmed", "unmined", "outputs", "inputs"}, callOrder,
	)
	require.Len(t, details, 2)
	require.Equal(t, confirmedTx.TxHash(), details[0].Hash)
	require.Equal(t, unminedTx.TxHash(), details[1].Hash)
}

// TestListTxDetailsWithOpsEmptyResult verifies that the shared ListTxDetails
// workflow returns a non-nil empty result when no rows match the range.
func TestListTxDetailsWithOpsEmptyResult(t *testing.T) {
	t.Parallel()

	// Arrange: Build one confirmed-only query whose backend range returns no
	// matching base rows.
	query := ListTxDetailsQuery{WalletID: 11, StartHeight: 50, EndHeight: 50}
	ops := &mockListTxDetailsOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("ListConfirmed", mock.Anything, uint32(11), int32(50), int32(50),
		false).Return([]TxDetailBase{}, nil).Once()

	// Act: Run the shared list-detail workflow.
	details, err := ListTxDetailsWithOps(context.Background(), query, ops)

	// Assert: Empty results are represented as an allocated empty slice, and
	// the helper does not attempt owned-edge loads for an empty base set.
	require.NoError(t, err)
	require.NotNil(t, details)
	require.Empty(t, details)
}

// TestSerializeMsgTxNil verifies that serializeMsgTx rejects a missing
// transaction pointer with the public invalid-param error.
func TestSerializeMsgTxNil(t *testing.T) {
	t.Parallel()

	_, err := serializeMsgTx(nil)
	require.ErrorIs(t, err, ErrInvalidParam)
}

// TestParseTxStatus verifies that stored numeric values map back to the public
// TxStatus enum and that unknown values fail loudly.
//
// The table keeps the setup identical for every case so the loop only varies
// the input status code and the expected result.
func TestParseTxStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		status  int64
		want    TxStatus
		wantErr error
	}{
		{name: "pending", status: 0, want: TxStatusPending},
		{name: "published", status: 1, want: TxStatusPublished},
		{name: "replaced", status: 2, want: TxStatusReplaced},
		{name: "failed", status: 3, want: TxStatusFailed},
		{name: "orphaned", status: 4, want: TxStatusOrphaned},
		{name: "invalid", status: 9, wantErr: ErrInvalidStatus},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseTxStatus(tc.status)
			require.ErrorIs(t, err, tc.wantErr)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestParseTxStatusNegativeValue verifies that parseTxStatus rejects negative
// stored values before they can map into the public TxStatus enum.
func TestParseTxStatusNegativeValue(t *testing.T) {
	t.Parallel()

	_, err := ParseTxStatus(-1)
	require.ErrorIs(t, err, ErrInvalidStatus)
}

// TestIsUnminedStatus verifies the delete-specific classification for each
// tx status.
func TestIsUnminedStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status TxStatus
		want   bool
	}{
		{name: "pending", status: TxStatusPending, want: true},
		{name: "published", status: TxStatusPublished, want: true},
		{name: "replaced", status: TxStatusReplaced, want: false},
		{name: "failed", status: TxStatusFailed, want: false},
		{name: "orphaned", status: TxStatusOrphaned, want: false},
		{name: "unknown", status: TxStatus(99), want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, test.want, IsUnminedStatus(test.status))
		})
	}
}

// TestBuildTxInfo verifies the shared row-to-domain conversion used by both
// SQL backends when returning a valid TxInfo value.
func TestBuildTxInfo(t *testing.T) {
	t.Parallel()

	// Arrange: Build one serialized transaction and one block fixture.
	tx := testRegularMsgTx()
	hash := tx.TxHash()
	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	blockHash := chainhash.Hash{1, 2, 3}
	block := &Block{
		Hash:      blockHash,
		Height:    77,
		Timestamp: time.Unix(500, 0),
	}

	// Act: Convert the normalized row fields into TxInfo.
	info, err := BuildTxInfo(
		hash[:], rawTx, time.Unix(600, 0).In(time.FixedZone("X", 3600)),
		block, int64(TxStatusPublished), "note",
	)
	require.NoError(t, err)

	// Assert: The resulting TxInfo preserves the expected public fields.
	require.Equal(t, hash, info.Hash)
	require.Equal(t, rawTx, info.SerializedTx)
	require.Equal(t, TxStatusPublished, info.Status)
	require.Equal(t, "note", info.Label)
	require.Equal(t, time.UTC, info.Received.Location())
	require.Equal(t, block, info.Block)
}

// TestBuildTxInfoInvalidHash verifies that BuildTxInfo rejects malformed hash
// bytes.
func TestBuildTxInfoInvalidHash(t *testing.T) {
	t.Parallel()

	tx := testRegularMsgTx()
	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	_, err = BuildTxInfo([]byte{1, 2, 3}, rawTx, time.Now(), nil,
		int64(TxStatusPending), "")
	require.Error(t, err)
}

// TestBuildTxInfoInvalidStatus verifies that BuildTxInfo rejects unknown status
// codes.
func TestBuildTxInfoInvalidStatus(t *testing.T) {
	t.Parallel()

	tx := testRegularMsgTx()
	hash := tx.TxHash()
	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	_, err = BuildTxInfo(hash[:], rawTx, time.Now(), nil, 9, "")
	require.ErrorIs(t, err, ErrInvalidStatus)
}

// TestValidateCreateTxParams verifies the shared CreateTx invariants that both
// SQL backends rely on before opening a write transaction.
//
// The cases vary only the CreateTx input data so the table-driven structure
// stays clear and does not need conditional setup inside the loop.
func TestValidateCreateTxParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		params       CreateTxParams
		wantErr      error
		wantParamErr error
	}{
		{
			name: "coinbase must be published",
			params: CreateTxParams{
				Tx:     testCoinbaseMsgTx(),
				Block:  testBlock(100),
				Status: TxStatusPending,
			},
			wantErr:      ErrInvalidStatus,
			wantParamErr: ErrInvalidParam,
		},
		{
			name: "coinbase requires block",
			params: CreateTxParams{
				Tx:     testCoinbaseMsgTx(),
				Status: TxStatusPublished,
			},
			wantErr:      ErrInvalidStatus,
			wantParamErr: ErrInvalidParam,
		},
		{
			name: "orphaned status rejected on create",
			params: CreateTxParams{
				Tx:     testRegularMsgTx(),
				Status: TxStatusOrphaned,
			},
			wantErr:      ErrInvalidStatus,
			wantParamErr: ErrInvalidParam,
		},
		{
			name: "failed status rejected on create",
			params: CreateTxParams{
				Tx:     testRegularMsgTx(),
				Status: TxStatusFailed,
			},
			wantErr:      ErrInvalidStatus,
			wantParamErr: ErrInvalidParam,
		},
		{
			name: "replaced status rejected on create",
			params: CreateTxParams{
				Tx:     testRegularMsgTx(),
				Status: TxStatusReplaced,
			},
			wantErr:      ErrInvalidStatus,
			wantParamErr: ErrInvalidParam,
		},
		{
			name: "credit index out of range",
			params: CreateTxParams{
				Tx:      testRegularMsgTx(),
				Credits: map[uint32]address.Address{2: nil},
				Status:  TxStatusPending,
			},
			wantErr:      ErrIndexOutOfRange,
			wantParamErr: ErrInvalidParam,
		},
		{
			name: "duplicate input outpoint",
			params: CreateTxParams{
				Tx: &wire.MsgTx{
					Version: wire.TxVersion,
					TxIn: []*wire.TxIn{{
						PreviousOutPoint: wire.OutPoint{
							Hash:  chainhash.Hash{1},
							Index: 0,
						},
					}, {
						PreviousOutPoint: wire.OutPoint{
							Hash:  chainhash.Hash{1},
							Index: 0,
						},
					}},
					TxOut: []*wire.TxOut{{Value: 1, PkScript: []byte{0x51}}},
				},
				Status: TxStatusPending,
			},
			wantErr:      ErrDuplicateInputOutPoint,
			wantParamErr: ErrInvalidParam,
		},
		{
			name: "confirmed create must be published",
			params: CreateTxParams{
				Tx:     testRegularMsgTx(),
				Block:  testBlock(101),
				Status: TxStatusPending,
			},
			wantErr:      ErrInvalidStatus,
			wantParamErr: ErrInvalidParam,
		},
		{
			name: "valid pending unmined transaction",
			params: CreateTxParams{
				Tx:      testRegularMsgTx(),
				Status:  TxStatusPending,
				Credits: map[uint32]address.Address{0: nil},
			},
		},
		{
			name: "valid published confirmed transaction",
			params: CreateTxParams{
				Tx:      testRegularMsgTx(),
				Block:   testBlock(102),
				Status:  TxStatusPublished,
				Credits: map[uint32]address.Address{0: nil},
			},
		},
		{
			name: "valid published coinbase facts",
			params: CreateTxParams{
				Tx:      testCoinbaseMsgTx(),
				Block:   testBlock(103),
				Status:  TxStatusPublished,
				Credits: map[uint32]address.Address{0: nil},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateCreateTxParams(tc.params)
			require.ErrorIs(t, err, tc.wantErr)
			require.ErrorIs(t, err, tc.wantParamErr)
		})
	}
}

// TestNewCreateTxRequest verifies that the shared CreateTx preparation step
// normalizes the request before either backend opens a write transaction.
func TestNewCreateTxRequest(t *testing.T) {
	t.Parallel()

	// Arrange: Build one valid request with a non-UTC received timestamp.
	params := CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(123, 0).In(time.FixedZone("X", 3600)),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
		Label:    "note",
	}

	// Act: Normalize it through NewCreateTxRequest.
	req, err := NewCreateTxRequest(params)
	require.NoError(t, err)

	wantRawTx, err := serializeMsgTx(params.Tx)
	require.NoError(t, err)

	// Assert: The prepared request caches the normalized transaction facts.
	require.Equal(t, params, req.Params)
	require.Equal(t, params.Tx.TxHash(), req.TxHash)
	require.Equal(t, wantRawTx, req.RawTx)
	require.Equal(t, time.UTC, req.Received.Location())
	require.False(t, req.IsCoinbase)
}

// TestCreateTxWithOpsInsert verifies that the shared CreateTx orchestration
// performs the full Insert path in order for one fresh transaction row.
func TestCreateTxWithOpsInsert(t *testing.T) {
	t.Parallel()

	// Arrange: Build one prepared CreateTx request and one mock adapter.
	req := testCreateTxRequest(t)

	var (
		insertReq CreateTxRequest
		creditsID int64
		inputsID  int64
	)

	ops := &mockCreateTxOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("LoadExisting", mock.Anything, req).Return(
		nil, ErrCreateTxExistingNotFound).Once()

	ops.On("PrepareBlock", mock.Anything, req).Return(nil).Once()

	ops.On("Insert", mock.Anything, req).Return(int64(11), nil).Run(
		func(args mock.Arguments) {
			reqArg, ok := args.Get(1).(CreateTxRequest)
			require.True(t, ok)

			insertReq = reqArg
		},
	).Once()

	ops.On("InsertCredits", mock.Anything, req, int64(11)).Return(nil).Run(
		func(args mock.Arguments) {
			txID, ok := args.Get(2).(int64)
			require.True(t, ok)

			creditsID = txID
		},
	).Once()

	ops.On("MarkInputsSpent", mock.Anything, req, int64(11)).Return(nil).Run(
		func(args mock.Arguments) {
			txID, ok := args.Get(2).(int64)
			require.True(t, ok)

			inputsID = txID
		},
	).Once()

	// Act: Run CreateTxWithOps.
	err := CreateTxWithOps(context.Background(), req, ops)
	require.NoError(t, err)

	// Assert: The shared flow uses the inserted tx ID consistently.
	require.Equal(t, int64(11), creditsID)
	require.Equal(t, int64(11), inputsID)
	require.Equal(t, req.TxHash, insertReq.TxHash)
}

// TestCreateTxWithOpsDuplicate verifies that the shared CreateTx helper maps an
// existing wallet-scoped tx hash to ErrTxAlreadyExists.
func TestCreateTxWithOpsDuplicate(t *testing.T) {
	t.Parallel()

	req := testCreateTxRequest(t)
	ops := &mockCreateTxOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("LoadExisting", mock.Anything, req).Return(
		&CreateTxExistingTarget{ID: 4}, nil).Once()

	err := CreateTxWithOps(context.Background(), req, ops)
	require.ErrorIs(t, err, ErrTxAlreadyExists)
}

// TestCreateTxWithOpsConfirmExisting verifies that the shared CreateTx flow can
// promote one existing unmined row to confirmed state instead of inserting a
// duplicate row.
func TestCreateTxWithOpsConfirmExisting(t *testing.T) {
	t.Parallel()

	req, err := NewCreateTxRequest(CreateTxParams{
		WalletID: 5,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	existing := CreateTxExistingTarget{
		ID:       7,
		Status:   TxStatusPending,
		HasBlock: false,
	}
	ops := &mockCreateTxOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("LoadExisting", mock.Anything, req).Return(&existing, nil).Once()

	ops.On("ConfirmExisting", mock.Anything, req, existing).Return(nil).Once()

	err = CreateTxWithOps(context.Background(), req, ops)
	require.NoError(t, err)
}

// TestCreateTxWithOpsReplaceConflicts verifies that the shared CreateTx flow
// rewrites direct conflict roots to replaced state after inserting the
// confirmed winner and before that winner claims the shared spent-parent edge.
func TestCreateTxWithOpsReplaceConflicts(t *testing.T) {
	t.Parallel()

	req, err := NewCreateTxRequest(CreateTxParams{
		WalletID: 5,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	rootIDs := []int64{5}
	rootHashes := []chainhash.Hash{{9}}
	ops := &mockCreateTxOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("LoadExisting", mock.Anything, req).Return(
		nil, ErrCreateTxExistingNotFound).Once()

	ops.On("PrepareBlock", mock.Anything, req).Return(nil).Once()

	ops.On("Insert", mock.Anything, req).Return(int64(11), nil).Once()

	ops.On("ListConflictTxns", mock.Anything, req).Return(
		rootIDs, rootHashes, nil,
	).Once()

	ops.On("ListUnminedTxRecords", mock.Anything, int64(5)).Return(
		[]UnminedTxRecord(nil), nil).Once()

	ops.On("ClearSpentUtxos", mock.Anything, int64(5), int64(5)).Return(nil).
		Once()

	ops.On("MarkTxnsReplaced", mock.Anything, int64(5), []int64{5}).Return(nil).
		Once()

	ops.On("InsertReplacementEdges", mock.Anything, int64(5), []int64{5},
		int64(11)).Return(nil).Once()

	ops.On("InsertCredits", mock.Anything, req, int64(11)).Return(nil).Once()

	ops.On("MarkInputsSpent", mock.Anything, req, int64(11)).Return(nil).Once()

	err = CreateTxWithOps(context.Background(), req, ops)
	require.NoError(t, err)
}

// testBlock builds a simple block fixture for CreateTx validation tests.
func testBlock(height uint32) *Block {
	return &Block{
		Hash:      chainhash.Hash{byte(height)},
		Height:    height,
		Timestamp: time.Unix(int64(height), 0),
	}
}

// testRegularMsgTx builds a minimal non-coinbase transaction fixture for the
// shared TxStore helper tests.
func testRegularMsgTx() *wire.MsgTx {
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{1}},
	})
	tx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})

	return tx
}

// testCoinbaseMsgTx builds a minimal coinbase transaction fixture.
func testCoinbaseMsgTx() *wire.MsgTx {
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: ^uint32(0)}})
	tx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})

	return tx
}

// testRegularMsgTxWithSeed builds one deterministic non-coinbase transaction
// fixture whose hash differs across seed values.
func testRegularMsgTxWithSeed(seed byte) *wire.MsgTx {
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{seed}},
	})
	tx.AddTxOut(&wire.TxOut{Value: int64(seed) + 1, PkScript: []byte{0x51}})

	return tx
}

// testTxDetailBase builds one normalized tx-detail base fixture for the shared
// detail workflow tests.
func testTxDetailBase(t *testing.T, id int64, tx *wire.MsgTx, block *Block,
	status TxStatus, label string) TxDetailBase {

	t.Helper()

	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	hash := tx.TxHash()

	return TxDetailBase{
		ID:       id,
		Hash:     append([]byte(nil), hash[:]...),
		RawTx:    rawTx,
		Received: time.Unix(id, 0).In(time.FixedZone("X", 3600)),
		Block:    block,
		Status:   int64(status),
		Label:    label,
	}
}

// testInputOutpoint builds the expected previous-outpoint fixture for a test
// transaction input.
func testInputOutpoint(txID int64, tx *wire.MsgTx) TxInputOutpoint {
	const inputIndex uint32 = 0

	txIn := tx.TxIn[inputIndex]

	return TxInputOutpoint{
		TxID:            txID,
		InputIndex:      inputIndex,
		PrevTxHash:      txIn.PreviousOutPoint.Hash,
		PrevOutputIndex: txIn.PreviousOutPoint.Index,
	}
}

// mockCreateTxOps is a mock implementation of CreateTxOps.
type mockCreateTxOps struct {
	mock.Mock
}

var _ CreateTxOps = (*mockCreateTxOps)(nil)

// LoadExisting implements CreateTxOps.
func (m *mockCreateTxOps) LoadExisting(ctx context.Context,
	req CreateTxRequest) (*CreateTxExistingTarget, error) {

	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	existing, ok := args.Get(0).(*CreateTxExistingTarget)
	if !ok {
		return nil, mockTypeError("LoadExisting result")
	}

	return existing, args.Error(1)
}

// ConfirmExisting implements CreateTxOps.
func (m *mockCreateTxOps) ConfirmExisting(ctx context.Context,
	req CreateTxRequest, existing CreateTxExistingTarget) error {

	args := m.Called(ctx, req, existing)

	return args.Error(0)
}

// PrepareBlock implements CreateTxOps.
func (m *mockCreateTxOps) PrepareBlock(ctx context.Context,
	req CreateTxRequest) error {

	args := m.Called(ctx, req)

	return args.Error(0)
}

// ListConflictTxns implements CreateTxOps.
func (m *mockCreateTxOps) ListConflictTxns(ctx context.Context,
	req CreateTxRequest) ([]int64, []chainhash.Hash, error) {

	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, nil, args.Error(2)
	}

	txIDs, ok := args.Get(0).([]int64)
	if !ok {
		return nil, nil, mockTypeError("ListConflictTxns ids")
	}

	hashes, ok := args.Get(1).([]chainhash.Hash)
	if !ok {
		return nil, nil, mockTypeError("ListConflictTxns hashes")
	}

	return txIDs, hashes, args.Error(2)
}

// LoadInvalidateTarget implements InvalidateUnminedTxOps.
func (m *mockCreateTxOps) LoadInvalidateTarget(ctx context.Context,
	walletID uint32,
	txHash chainhash.Hash) (InvalidateUnminedTxTarget, error) {

	var zeroTarget InvalidateUnminedTxTarget

	args := m.Called(ctx, walletID, txHash)
	if args.Get(0) == nil {
		return zeroTarget, args.Error(1)
	}

	target, ok := args.Get(0).(InvalidateUnminedTxTarget)
	if !ok {
		return zeroTarget, mockTypeError("LoadInvalidateTarget result")
	}

	return target, args.Error(1)
}

// ListUnminedTxRecords implements InvalidateUnminedTxOps.
func (m *mockCreateTxOps) ListUnminedTxRecords(ctx context.Context,
	walletID int64) ([]UnminedTxRecord, error) {

	args := m.Called(ctx, walletID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	records, ok := args.Get(0).([]UnminedTxRecord)
	if !ok {
		return nil, mockTypeError("ListUnminedTxRecords result")
	}

	return records, args.Error(1)
}

// ClearSpentUtxos implements InvalidateUnminedTxOps.
func (m *mockCreateTxOps) ClearSpentUtxos(ctx context.Context, walletID int64,
	txID int64) error {

	args := m.Called(ctx, walletID, txID)

	return args.Error(0)
}

// MarkTxnsFailed implements InvalidateUnminedTxOps.
func (m *mockCreateTxOps) MarkTxnsFailed(ctx context.Context, walletID int64,
	txIDs []int64) error {

	args := m.Called(ctx, walletID, txIDs)

	return args.Error(0)
}

// MarkTxnsReplaced implements CreateTxOps.
func (m *mockCreateTxOps) MarkTxnsReplaced(ctx context.Context, walletID int64,
	txIDs []int64) error {

	args := m.Called(ctx, walletID, txIDs)

	return args.Error(0)
}

// InsertReplacementEdges implements CreateTxOps.
func (m *mockCreateTxOps) InsertReplacementEdges(ctx context.Context,
	walletID int64, replacedTxIDs []int64, replacementTxID int64) error {

	args := m.Called(ctx, walletID, replacedTxIDs, replacementTxID)

	return args.Error(0)
}

// Insert implements CreateTxOps.
func (m *mockCreateTxOps) Insert(ctx context.Context,
	req CreateTxRequest) (int64, error) {

	args := m.Called(ctx, req)

	txID, ok := args.Get(0).(int64)
	if !ok {
		return 0, mockTypeError("Insert result")
	}

	return txID, args.Error(1)
}

// InsertCredits implements CreateTxOps.
func (m *mockCreateTxOps) InsertCredits(ctx context.Context,
	req CreateTxRequest, txID int64) error {

	args := m.Called(ctx, req, txID)

	return args.Error(0)
}

// MarkInputsSpent implements CreateTxOps.
func (m *mockCreateTxOps) MarkInputsSpent(ctx context.Context,
	req CreateTxRequest, txID int64) error {

	args := m.Called(ctx, req, txID)

	return args.Error(0)
}

// mockGetTxDetailOps is a mock implementation of GetTxDetailOps.
type mockGetTxDetailOps struct {
	mock.Mock
}

var _ GetTxDetailOps = (*mockGetTxDetailOps)(nil)

// LoadBase implements GetTxDetailOps.
func (m *mockGetTxDetailOps) LoadBase(ctx context.Context,
	query GetTxDetailQuery) (TxDetailBase, error) {

	args := m.Called(ctx, query)

	base, ok := args.Get(0).(TxDetailBase)
	if !ok {
		return TxDetailBase{}, mockTypeError("LoadBase result")
	}

	return base, args.Error(1)
}

// LoadOwnedOutputs implements GetTxDetailOps.
func (m *mockGetTxDetailOps) LoadOwnedOutputs(ctx context.Context,
	walletID uint32, txIDs []int64) (map[int64][]TxOwnedOutput, error) {

	args := m.Called(ctx, walletID, txIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	outputs, ok := args.Get(0).(map[int64][]TxOwnedOutput)
	if !ok {
		return nil, mockTypeError("LoadOwnedOutputs result")
	}

	return outputs, args.Error(1)
}

// LoadOwnedInputs implements GetTxDetailOps.
func (m *mockGetTxDetailOps) LoadOwnedInputs(ctx context.Context,
	walletID uint32, inputOutpoints []TxInputOutpoint) (
	map[int64][]TxOwnedInput, error) {

	args := m.Called(ctx, walletID, inputOutpoints)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	inputs, ok := args.Get(0).(map[int64][]TxOwnedInput)
	if !ok {
		return nil, mockTypeError("LoadOwnedInputs result")
	}

	return inputs, args.Error(1)
}

// mockListTxDetailsOps is a mock implementation of ListTxDetailsOps.
type mockListTxDetailsOps struct {
	mock.Mock
}

var _ ListTxDetailsOps = (*mockListTxDetailsOps)(nil)

// ListUnmined implements ListTxDetailsOps.
func (m *mockListTxDetailsOps) ListUnmined(ctx context.Context,
	walletID uint32) ([]TxDetailBase, error) {

	args := m.Called(ctx, walletID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	bases, ok := args.Get(0).([]TxDetailBase)
	if !ok {
		return nil, mockTypeError("ListUnmined result")
	}

	return bases, args.Error(1)
}

// ListConfirmed implements ListTxDetailsOps.
func (m *mockListTxDetailsOps) ListConfirmed(ctx context.Context,
	walletID uint32, startHeight, endHeight int32,
	reverse bool) ([]TxDetailBase, error) {

	args := m.Called(ctx, walletID, startHeight, endHeight, reverse)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	bases, ok := args.Get(0).([]TxDetailBase)
	if !ok {
		return nil, mockTypeError("ListConfirmed result")
	}

	return bases, args.Error(1)
}

// LoadOwnedOutputs implements ListTxDetailsOps.
func (m *mockListTxDetailsOps) LoadOwnedOutputs(ctx context.Context,
	walletID uint32, txIDs []int64) (map[int64][]TxOwnedOutput, error) {

	args := m.Called(ctx, walletID, txIDs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	outputs, ok := args.Get(0).(map[int64][]TxOwnedOutput)
	if !ok {
		return nil, mockTypeError("LoadOwnedOutputs result")
	}

	return outputs, args.Error(1)
}

// LoadOwnedInputs implements ListTxDetailsOps.
func (m *mockListTxDetailsOps) LoadOwnedInputs(ctx context.Context,
	walletID uint32, inputOutpoints []TxInputOutpoint) (
	map[int64][]TxOwnedInput, error) {

	args := m.Called(ctx, walletID, inputOutpoints)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	inputs, ok := args.Get(0).(map[int64][]TxOwnedInput)
	if !ok {
		return nil, mockTypeError("LoadOwnedInputs result")
	}

	return inputs, args.Error(1)
}

// mockUpdateTxOps is a mock implementation of UpdateTxOps.
type mockUpdateTxOps struct {
	mock.Mock
}

var _ UpdateTxOps = (*mockUpdateTxOps)(nil)

// LoadIsCoinbase implements UpdateTxOps.
func (m *mockUpdateTxOps) LoadIsCoinbase(ctx context.Context, walletID uint32,
	txHash chainhash.Hash) (bool, error) {

	args := m.Called(ctx, walletID, txHash)

	isCoinbase, ok := args.Get(0).(bool)
	if !ok {
		return false, mockTypeError("LoadIsCoinbase result")
	}

	return isCoinbase, args.Error(1)
}

// PrepareState implements UpdateTxOps.
func (m *mockUpdateTxOps) PrepareState(ctx context.Context,
	state UpdateTxState) error {

	args := m.Called(ctx, state)

	return args.Error(0)
}

// UpdateLabel implements UpdateTxOps.
func (m *mockUpdateTxOps) UpdateLabel(ctx context.Context, walletID uint32,
	txHash chainhash.Hash, label string) error {

	args := m.Called(ctx, walletID, txHash, label)

	return args.Error(0)
}

// UpdateState implements UpdateTxOps.
func (m *mockUpdateTxOps) UpdateState(ctx context.Context, walletID uint32,
	txHash chainhash.Hash, state UpdateTxState) error {

	args := m.Called(ctx, walletID, txHash, state)

	return args.Error(0)
}

// testCreateTxRequest builds one valid normalized CreateTx request for the
// shared CreateTx orchestration tests.
func testCreateTxRequest(t *testing.T) CreateTxRequest {
	t.Helper()

	req, err := NewCreateTxRequest(CreateTxParams{
		WalletID: 5,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Status:   TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	return req
}

var errConflictMarkFailed = errors.New("mark failed")

// TestCollectConflictDescendants verifies that the helper derives the direct
// root IDs and descendant IDs from the current unmined graph snapshot.
func TestCollectConflictDescendants(t *testing.T) {
	t.Parallel()

	candidates := []UnminedTxRecord{{
		ID:   12,
		Hash: chainhash.Hash{2},
		Tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0},
		}}},
	}, {
		ID:   13,
		Hash: chainhash.Hash{3},
		Tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{2}, Index: 0},
		}}},
	}}
	ops := &mockCreateTxOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	rootIDs := []int64{11, 12}
	rootHashes := []chainhash.Hash{{1}, {2}}

	ops.On("ListUnminedTxRecords", mock.Anything, int64(7)).Return(
		candidates, nil).Once()

	descendantIDs, err := collectConflictDescendants(
		context.Background(), 7, rootHashes, rootIDs, ops,
	)
	require.NoError(t, err)
	require.Equal(t, []int64{13}, descendantIDs)
}

// TestHandleTxConflicts verifies the shared replacement flow for
// one direct conflict root and its dependent descendants.
func TestHandleTxConflicts(t *testing.T) {
	t.Parallel()

	rootHash := chainhash.Hash{1}
	childHash := chainhash.Hash{2}
	grandchildHash := chainhash.Hash{3}
	req, err := NewCreateTxRequest(CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
	})
	require.NoError(t, err)

	candidates := []UnminedTxRecord{{
		ID:   2,
		Hash: childHash,
		Tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: rootHash, Index: 0},
		}}},
	}, {
		ID:   3,
		Hash: grandchildHash,
		Tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: childHash, Index: 0},
		}}},
	}}

	ops := &mockCreateTxOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("ListConflictTxns", mock.Anything, req).Return(
		[]int64{1}, []chainhash.Hash{rootHash}, nil,
	).Once()

	ops.On("ListUnminedTxRecords", mock.Anything, int64(7)).Return(
		candidates, nil).Once()

	ops.On("ClearSpentUtxos", mock.Anything, int64(7), int64(1)).Return(nil).
		Once()

	ops.On("MarkTxnsReplaced", mock.Anything, int64(7), []int64{1}).Return(nil).
		Once()

	ops.On("InsertReplacementEdges", mock.Anything, int64(7), []int64{1},
		int64(9)).Return(nil).Once()

	ops.On("ClearSpentUtxos", mock.Anything, int64(7), int64(2)).Return(nil).
		Once()

	ops.On("ClearSpentUtxos", mock.Anything, int64(7), int64(3)).Return(nil).
		Once()

	ops.On("MarkTxnsFailed", mock.Anything, int64(7), []int64{2, 3}).
		Return(nil).Once()

	err = handleTxConflicts(t.Context(), req, 9, ops)
	require.NoError(t, err)
}

// TestHandleTxConflictsKeepsDirectRootsReplaced verifies that a
// direct conflict root stays replaced even when it also spends another direct
// root and would otherwise appear in the descendant walk.
func TestHandleTxConflictsKeepsDirectRootsReplaced(t *testing.T) {
	t.Parallel()

	rootAHash := chainhash.Hash{1}
	rootBHash := chainhash.Hash{2}
	childHash := chainhash.Hash{3}
	req, err := NewCreateTxRequest(CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
	})
	require.NoError(t, err)

	ops := &mockCreateTxOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("ListConflictTxns", mock.Anything, req).Return(
		[]int64{1, 2},
		[]chainhash.Hash{rootAHash, rootBHash},
		nil,
	).Once()

	ops.On("ListUnminedTxRecords", mock.Anything, int64(7)).Return(
		[]UnminedTxRecord{{
			ID:   2,
			Hash: rootBHash,
			Tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Hash: rootAHash, Index: 0},
			}}},
		}, {
			ID:   3,
			Hash: childHash,
			Tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Hash: rootBHash, Index: 0},
			}}},
		}}, nil).Once()

	ops.On("ClearSpentUtxos", mock.Anything, int64(7), int64(1)).Return(nil).
		Once()
	ops.On("ClearSpentUtxos", mock.Anything, int64(7), int64(2)).Return(nil).
		Once()
	ops.On("MarkTxnsReplaced", mock.Anything, int64(7), []int64{1, 2}).
		Return(nil).Once()
	ops.On("InsertReplacementEdges", mock.Anything, int64(7), []int64{1, 2},
		int64(9)).Return(nil).Once()
	ops.On("ClearSpentUtxos", mock.Anything, int64(7), int64(3)).Return(nil).
		Once()
	ops.On("MarkTxnsFailed", mock.Anything, int64(7), []int64{3}).Return(nil).
		Once()

	err = handleTxConflicts(t.Context(), req, 9, ops)
	require.NoError(t, err)
}

// TestHandleTxConflictsNoDescendants verifies that the helper
// skips the descendant-failure batch when no dependent branch exists.
func TestHandleTxConflictsNoDescendants(t *testing.T) {
	t.Parallel()

	req, err := NewCreateTxRequest(CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
	})
	require.NoError(t, err)

	ops := &mockCreateTxOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("ListConflictTxns", mock.Anything, req).Return(
		[]int64{1}, []chainhash.Hash{{1}}, nil,
	).Once()

	ops.On("ListUnminedTxRecords", mock.Anything, int64(7)).Return(
		[]UnminedTxRecord(nil), nil).Once()

	ops.On("ClearSpentUtxos", mock.Anything, int64(7), int64(1)).Return(nil).
		Once()
	ops.On("MarkTxnsReplaced", mock.Anything, int64(7), []int64{1}).Return(nil).
		Once()
	ops.On("InsertReplacementEdges", mock.Anything, int64(7), []int64{1},
		int64(9)).Return(nil).Once()

	err = handleTxConflicts(t.Context(), req, 9, ops)
	require.NoError(t, err)
}

// TestHandleTxConflictsMarkFailedError verifies that the helper records
// replacement edges before returning descendant failure errors.
func TestHandleTxConflictsMarkFailedError(t *testing.T) {
	t.Parallel()

	req, err := NewCreateTxRequest(CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
	})
	require.NoError(t, err)

	ops := &mockCreateTxOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("ListConflictTxns", mock.Anything, req).Return(
		[]int64{1}, []chainhash.Hash{{1}}, nil,
	).Once()

	ops.On("ListUnminedTxRecords", mock.Anything, int64(7)).Return(
		[]UnminedTxRecord{{
			ID:   2,
			Hash: chainhash.Hash{2},
			Tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{1},
					Index: 0,
				},
			}}},
		}}, nil).Once()

	ops.On("ClearSpentUtxos", mock.Anything, int64(7), int64(1)).Return(nil).
		Once()
	ops.On("MarkTxnsReplaced", mock.Anything, int64(7), []int64{1}).Return(nil).
		Once()
	ops.On("InsertReplacementEdges", mock.Anything, int64(7), []int64{1},
		int64(9)).Return(nil).Once()
	ops.On("ClearSpentUtxos", mock.Anything, int64(7), int64(2)).Return(nil).
		Once()
	ops.On("MarkTxnsFailed", mock.Anything, int64(7), []int64{2}).Return(
		errConflictMarkFailed).Once()

	err = handleTxConflicts(t.Context(), req, 9, ops)
	require.ErrorIs(t, err, errConflictMarkFailed)
	require.ErrorContains(t, err, "mark conflict descendants failed")
}

// TestUpdateTxWithOpsLabelAndState verifies that the shared UpdateTx workflow
// can apply both a label patch and a state patch in one atomic sequence.
func TestUpdateTxWithOpsLabelAndState(t *testing.T) {
	t.Parallel()

	// Arrange: Build one request with both a label patch and a state patch.
	label := "note"
	params := UpdateTxParams{
		WalletID: 5,
		Txid:     chainhash.Hash{1},
		Label:    &label,
		State: &UpdateTxState{
			Status: TxStatusPublished,
		},
	}

	var (
		updatedLabel string
		updatedState UpdateTxState
	)

	ops := &mockUpdateTxOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("LoadIsCoinbase", mock.Anything, uint32(5), chainhash.Hash{1}).
		Return(false, nil).Once()

	ops.On("PrepareState", mock.Anything, UpdateTxState{
		Status: TxStatusPublished,
	}).Return(nil).Once()

	ops.On("UpdateLabel", mock.Anything, uint32(5), chainhash.Hash{1},
		label).Return(nil).Run(func(args mock.Arguments) {
		labelArg, ok := args.Get(3).(string)
		require.True(t, ok)

		updatedLabel = labelArg
	}).Once()

	ops.On("UpdateState", mock.Anything, uint32(5), chainhash.Hash{1},
		UpdateTxState{Status: TxStatusPublished}).Return(nil).Run(
		func(args mock.Arguments) {
			stateArg, ok := args.Get(3).(UpdateTxState)
			require.True(t, ok)

			updatedState = stateArg
		},
	).Once()

	// Act: Run UpdateTxWithOps against a stub backend adapter.
	err := UpdateTxWithOps(context.Background(), params, ops)
	require.NoError(t, err)

	// Assert: The shared flow applies both patches.
	require.Equal(t, label, updatedLabel)
	require.Equal(t, TxStatusPublished, updatedState.Status)
}

// TestUpdateTxWithOpsEmptyPatch verifies that the shared UpdateTx helper
// rejects requests that do not ask to mutate any field.
func TestUpdateTxWithOpsEmptyPatch(t *testing.T) {
	t.Parallel()

	params := UpdateTxParams{
		WalletID: 5,
		Txid:     chainhash.Hash{1},
	}
	ops := &mockUpdateTxOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("LoadIsCoinbase", mock.Anything, uint32(5), chainhash.Hash{1}).
		Return(false, nil).Once()

	err := UpdateTxWithOps(context.Background(), params, ops)
	require.ErrorIs(t, err, ErrInvalidParam)
}

// TestUpdateTxWithOpsRejectsInvalidatingStates verifies that UpdateTx rejects
// branch-affecting state transitions before any backend write begins.
func TestUpdateTxWithOpsRejectsInvalidatingStates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		isCoinbase bool
		state      UpdateTxState
	}{
		{
			name: "failed rejected",
			state: UpdateTxState{
				Status: TxStatusFailed,
			},
		},
		{
			name: "replaced rejected",
			state: UpdateTxState{
				Status: TxStatusReplaced,
			},
		},
		{
			name: "orphaned rejected",
			state: UpdateTxState{
				Status: TxStatusOrphaned,
			},
		},
		{
			name:       "coinbase orphaned rejected",
			isCoinbase: true,
			state: UpdateTxState{
				Status: TxStatusOrphaned,
			},
		},
		{
			name:       "coinbase confirmed patch rejected",
			isCoinbase: true,
			state: UpdateTxState{
				Status: TxStatusPublished,
				Block:  testBlock(55),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			params := UpdateTxParams{
				WalletID: 5,
				Txid:     chainhash.Hash{1},
				State:    &test.state,
			}
			ops := &mockUpdateTxOps{}
			t.Cleanup(func() {
				ops.AssertExpectations(t)
			})

			ops.On(
				"LoadIsCoinbase", mock.Anything, uint32(5), chainhash.Hash{1},
			).Return(test.isCoinbase, nil).Once()

			err := UpdateTxWithOps(context.Background(), params, ops)
			require.ErrorIs(t, err, ErrInvalidParam)
			require.ErrorIs(t, err, ErrInvalidStatus)
		})
	}
}

var errCreateTxTest = errors.New("create tx test")

// TestCheckReuseCreateTx verifies the shared reuse decision for existing rows.
func TestCheckReuseCreateTx(t *testing.T) {
	t.Parallel()

	coinbaseReq, err := NewCreateTxRequest(CreateTxParams{
		WalletID: 9,
		Tx:       testCoinbaseMsgTx(),
		Received: time.Unix(555, 0),
		Block:    testBlock(22),
		Status:   TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	confirmedReq, err := NewCreateTxRequest(CreateTxParams{
		WalletID: 9,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(556, 0),
		Block:    testBlock(23),
		Status:   TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	tests := []struct {
		name     string
		req      CreateTxRequest
		existing CreateTxExistingTarget
		want     bool
	}{
		{
			name: "confirmed unmined row reused",
			req:  confirmedReq,
			existing: CreateTxExistingTarget{
				Status: TxStatusPending,
			},
			want: true,
		},
		{
			name: "missing block not reused",
			req:  testCreateTxRequest(t),
			existing: CreateTxExistingTarget{
				Status: TxStatusPending,
			},
		},
		{
			name: "existing confirmed row not reused",
			req:  confirmedReq,
			existing: CreateTxExistingTarget{
				Status:   TxStatusPublished,
				HasBlock: true,
			},
		},
		{
			name: "non coinbase orphan not reused",
			req:  confirmedReq,
			existing: CreateTxExistingTarget{
				Status: TxStatusOrphaned,
			},
		},
		{
			name: "orphaned coinbase reused",
			req:  coinbaseReq,
			existing: CreateTxExistingTarget{
				Status:     TxStatusOrphaned,
				IsCoinbase: true,
			},
			want: true,
		},
		{
			name: "coinbase row not reused for non coinbase tx",
			req:  confirmedReq,
			existing: CreateTxExistingTarget{
				Status:     TxStatusOrphaned,
				IsCoinbase: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, test.want,
				checkReuseCreateTx(test.req, test.existing))
		})
	}
}

// TestLoadCreateTxExisting verifies not-found and wrapped-error handling for
// the shared existing-row lookup.
func TestLoadCreateTxExisting(t *testing.T) {
	t.Parallel()

	req := testCreateTxRequest(t)
	ops := &mockCreateTxOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("LoadExisting", mock.Anything, req).Return(
		nil, ErrCreateTxExistingNotFound).Once()

	existing, found, err := loadCreateTxExisting(context.Background(), req, ops)
	require.NoError(t, err)
	require.False(t, found)
	require.Nil(t, existing)

	ops.On("LoadExisting", mock.Anything, req).Return(nil, nil).Once()

	existing, found, err = loadCreateTxExisting(context.Background(), req, ops)
	require.NoError(t, err)
	require.False(t, found)
	require.Nil(t, existing)

	ops.On("LoadExisting", mock.Anything, req).Return(
		nil, errCreateTxTest,
	).Once()

	_, _, err = loadCreateTxExisting(context.Background(), req, ops)
	require.ErrorIs(t, err, errCreateTxTest)
	require.ErrorContains(t, err, "load create tx target")
}

// TestHandleRootTxnsClearError verifies that root spend-clearing failures are
// returned before the helper mutates any later replacement state.
func TestHandleRootTxnsClearError(t *testing.T) {
	t.Parallel()

	ops := &mockCreateTxOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("ClearSpentUtxos", mock.Anything, int64(9), int64(1)).Return(
		errCreateTxTest).Once()

	err := handleRootTxns(context.Background(), 9, []int64{1}, 11, ops)
	require.ErrorIs(t, err, errCreateTxTest)
	require.ErrorContains(t, err, "clear replaced root spent utxos")
}

// TestHandleTxConflictsEdgeError verifies that replacement edge writes are
// wrapped after the branch state has been updated.
func TestHandleTxConflictsEdgeError(t *testing.T) {
	t.Parallel()

	req, err := NewCreateTxRequest(CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
	})
	require.NoError(t, err)

	ops := &mockCreateTxOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("ListConflictTxns", mock.Anything, req).Return(
		[]int64{1}, []chainhash.Hash{{1}}, nil,
	).Once()
	ops.On("ListUnminedTxRecords", mock.Anything, int64(7)).Return(
		[]UnminedTxRecord(nil), nil).Once()
	ops.On("ClearSpentUtxos", mock.Anything, int64(7), int64(1)).Return(
		nil,
	).Once()
	ops.On("MarkTxnsReplaced", mock.Anything, int64(7), []int64{1}).Return(
		nil,
	).Once()
	ops.On("InsertReplacementEdges", mock.Anything, int64(7), []int64{1},
		int64(9)).Return(errCreateTxTest).Once()

	err = handleTxConflicts(context.Background(), req, 9, ops)
	require.ErrorIs(t, err, errCreateTxTest)
	require.ErrorContains(t, err, "record conflict replacement edges")
}

// TestHandleTxConflictsListError verifies that the helper returns
// descendant-discovery load failures before mutating the branch.
func TestHandleTxConflictsListError(t *testing.T) {
	t.Parallel()

	req, err := NewCreateTxRequest(CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
	})
	require.NoError(t, err)

	ops := &mockCreateTxOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("ListConflictTxns", mock.Anything, req).Return(
		[]int64{1}, []chainhash.Hash{{1}}, nil,
	).Once()
	ops.On("ListUnminedTxRecords", mock.Anything, int64(7)).Return(
		nil, errCreateTxTest).Once()

	err = handleTxConflicts(context.Background(), req, 9, ops)
	require.ErrorIs(t, err, errCreateTxTest)
	require.ErrorContains(t, err, "list create tx conflict candidates")
}

// TestHandleTxConflictsMarkReplacedError verifies that the helper wraps
// direct-root replacement failures.
func TestHandleTxConflictsMarkReplacedError(t *testing.T) {
	t.Parallel()

	req, err := NewCreateTxRequest(CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
	})
	require.NoError(t, err)

	ops := &mockCreateTxOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("ListConflictTxns", mock.Anything, req).Return(
		[]int64{1}, []chainhash.Hash{{1}}, nil,
	).Once()
	ops.On("ListUnminedTxRecords", mock.Anything, int64(7)).Return(
		[]UnminedTxRecord(nil), nil).Once()
	ops.On("ClearSpentUtxos", mock.Anything, int64(7), int64(1)).Return(
		nil,
	).Once()
	ops.On("MarkTxnsReplaced", mock.Anything, int64(7), []int64{1}).Return(
		errCreateTxTest).Once()

	err = handleTxConflicts(context.Background(), req, 9, ops)
	require.ErrorIs(t, err, errCreateTxTest)
	require.ErrorContains(t, err, "mark direct conflicts replaced")
}

// TestValidateUpdateTxState verifies the remaining shared UpdateTx state
// invariants not covered by the integration tests.
func TestValidateUpdateTxState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		state      UpdateTxState
		isCoinbase bool
		wantErr    error
	}{
		{
			name:    "invalid status",
			state:   UpdateTxState{Status: TxStatus(99)},
			wantErr: ErrInvalidParam,
		},
		{
			name:    "non coinbase cannot orphan",
			state:   UpdateTxState{Status: TxStatusOrphaned},
			wantErr: ErrInvalidParam,
		},
		{
			name: "confirmed must be published",
			state: UpdateTxState{
				Status: TxStatusFailed,
				Block:  testBlock(44),
			},
			wantErr: ErrInvalidParam,
		},
		{
			name:       "coinbase patch rejected",
			state:      UpdateTxState{Status: TxStatusPublished},
			isCoinbase: true,
			wantErr:    ErrInvalidParam,
		},
		{
			name: "published confirmed valid",
			state: UpdateTxState{
				Status: TxStatusPublished,
				Block:  testBlock(45),
			},
			wantErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := validateUpdateTxState(test.state, test.isCoinbase)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
				return
			}

			require.NoError(t, err)
		})
	}
}
