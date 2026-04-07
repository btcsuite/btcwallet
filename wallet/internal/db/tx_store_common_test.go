package db

import (
	"bytes"
	"context"
	"errors"
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

			got, err := parseTxStatus(tc.status)
			require.ErrorIs(t, err, tc.wantErr)
			require.Equal(t, tc.want, got)
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
	info, err := buildTxInfo(
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

// TestBuildTxInfoInvalidHash verifies that buildTxInfo rejects malformed hash
// bytes.
func TestBuildTxInfoInvalidHash(t *testing.T) {
	t.Parallel()

	tx := testRegularMsgTx()
	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	_, err = buildTxInfo([]byte{1, 2, 3}, rawTx, time.Now(), nil,
		int64(TxStatusPending), "")
	require.Error(t, err)
}

// TestBuildTxInfoInvalidStatus verifies that buildTxInfo rejects unknown status
// codes.
func TestBuildTxInfoInvalidStatus(t *testing.T) {
	t.Parallel()

	tx := testRegularMsgTx()
	hash := tx.TxHash()
	rawTx, err := serializeMsgTx(tx)
	require.NoError(t, err)

	_, err = buildTxInfo(hash[:], rawTx, time.Now(), nil, 9, "")
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

	// Act: Normalize it through newCreateTxRequest.
	req, err := newCreateTxRequest(params)
	require.NoError(t, err)

	wantRawTx, err := serializeMsgTx(params.Tx)
	require.NoError(t, err)

	// Assert: The prepared request caches the normalized transaction facts.
	require.Equal(t, params, req.params)
	require.Equal(t, params.Tx.TxHash(), req.txHash)
	require.Equal(t, wantRawTx, req.rawTx)
	require.Equal(t, time.UTC, req.received.Location())
	require.False(t, req.isCoinbase)
}

// TestCreateTxWithOpsInsert verifies that the shared CreateTx orchestration
// performs the full insert path in order for one fresh transaction row.
func TestCreateTxWithOpsInsert(t *testing.T) {
	t.Parallel()

	// Arrange: Build one prepared CreateTx request and one mock adapter.
	req := testCreateTxRequest(t)

	var (
		insertReq createTxRequest
		creditsID int64
		inputsID  int64
	)

	ops := &mockCreateTxOps{}
	t.Cleanup(func() { ops.AssertExpectations(t) })

	ops.On("loadExisting", mock.Anything, req).Return(
		nil, errCreateTxExistingNotFound).Once()

	ops.On("prepareBlock", mock.Anything, req).Return(nil).Once()

	ops.On("insert", mock.Anything, req).Return(int64(11), nil).Run(
		func(args mock.Arguments) {
			reqArg, ok := args.Get(1).(createTxRequest)
			require.True(t, ok)
			insertReq = reqArg
		},
	).Once()

	ops.On("insertCredits", mock.Anything, req, int64(11)).Return(nil).Run(
		func(args mock.Arguments) {
			txID, ok := args.Get(2).(int64)
			require.True(t, ok)
			creditsID = txID
		},
	).Once()

	ops.On("markInputsSpent", mock.Anything, req, int64(11)).Return(nil).Run(
		func(args mock.Arguments) {
			txID, ok := args.Get(2).(int64)
			require.True(t, ok)
			inputsID = txID
		},
	).Once()

	// Act: Run createTxWithOps.
	err := createTxWithOps(context.Background(), req, ops)
	require.NoError(t, err)

	// Assert: The shared flow uses the inserted tx ID consistently.
	require.Equal(t, int64(11), creditsID)
	require.Equal(t, int64(11), inputsID)
	require.Equal(t, req.txHash, insertReq.txHash)
}

// TestCreateTxWithOpsDuplicate verifies that the shared CreateTx helper maps an
// existing wallet-scoped tx hash to ErrTxAlreadyExists.
func TestCreateTxWithOpsDuplicate(t *testing.T) {
	t.Parallel()

	req := testCreateTxRequest(t)
	ops := &mockCreateTxOps{}
	t.Cleanup(func() { ops.AssertExpectations(t) })

	ops.On("loadExisting", mock.Anything, req).Return(
		&createTxExistingTarget{id: 4}, nil).Once()

	err := createTxWithOps(context.Background(), req, ops)
	require.ErrorIs(t, err, ErrTxAlreadyExists)
}

// TestCreateTxWithOpsConfirmExisting verifies that the shared CreateTx flow can
// promote one existing unmined row to confirmed state instead of inserting a
// duplicate row.
func TestCreateTxWithOpsConfirmExisting(t *testing.T) {
	t.Parallel()

	req, err := newCreateTxRequest(CreateTxParams{
		WalletID: 5,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	existing := createTxExistingTarget{
		id:       7,
		status:   TxStatusPending,
		hasBlock: false,
	}
	ops := &mockCreateTxOps{}
	t.Cleanup(func() { ops.AssertExpectations(t) })

	ops.On("loadExisting", mock.Anything, req).Return(&existing, nil).Once()

	ops.On("confirmExisting", mock.Anything, req, existing).Return(nil).Once()

	err = createTxWithOps(context.Background(), req, ops)
	require.NoError(t, err)
}

// TestCreateTxWithOpsReplaceConflicts verifies that the shared CreateTx flow
// rewrites direct conflict roots to replaced state after inserting the
// confirmed winner and before that winner claims the shared spent-parent edge.
func TestCreateTxWithOpsReplaceConflicts(t *testing.T) {
	t.Parallel()

	req, err := newCreateTxRequest(CreateTxParams{
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
	t.Cleanup(func() { ops.AssertExpectations(t) })

	ops.On("loadExisting", mock.Anything, req).Return(
		nil, errCreateTxExistingNotFound).Once()

	ops.On("prepareBlock", mock.Anything, req).Return(nil).Once()

	ops.On("insert", mock.Anything, req).Return(int64(11), nil).Once()

	ops.On("listConflictTxns", mock.Anything, req).Return(
		rootIDs, rootHashes, nil,
	).Once()

	ops.On("listUnminedTxRecords", mock.Anything, int64(5)).Return(
		[]unminedTxRecord(nil), nil).Once()

	ops.On("clearSpentUtxos", mock.Anything, int64(5), int64(5)).Return(nil).
		Once()

	ops.On("markTxnsReplaced", mock.Anything, int64(5), []int64{5}).Return(nil).
		Once()

	ops.On("insertReplacementEdges", mock.Anything, int64(5), []int64{5},
		int64(11)).Return(nil).Once()

	ops.On("insertCredits", mock.Anything, req, int64(11)).Return(nil).Once()

	ops.On("markInputsSpent", mock.Anything, req, int64(11)).Return(nil).Once()

	err = createTxWithOps(context.Background(), req, ops)
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

// mockCreateTxOps is a mock implementation of createTxOps.
type mockCreateTxOps struct {
	mock.Mock
}

var _ createTxOps = (*mockCreateTxOps)(nil)

// loadExisting implements createTxOps.
func (m *mockCreateTxOps) loadExisting(ctx context.Context,
	req createTxRequest) (*createTxExistingTarget, error) {

	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	existing, ok := args.Get(0).(*createTxExistingTarget)
	if !ok {
		return nil, mockTypeError("loadExisting result")
	}

	return existing, args.Error(1)
}

// confirmExisting implements createTxOps.
func (m *mockCreateTxOps) confirmExisting(ctx context.Context,
	req createTxRequest, existing createTxExistingTarget) error {

	args := m.Called(ctx, req, existing)

	return args.Error(0)
}

// prepareBlock implements createTxOps.
func (m *mockCreateTxOps) prepareBlock(ctx context.Context,
	req createTxRequest) error {

	args := m.Called(ctx, req)

	return args.Error(0)
}

// listConflictTxns implements createTxOps.
func (m *mockCreateTxOps) listConflictTxns(ctx context.Context,
	req createTxRequest) ([]int64, []chainhash.Hash, error) {

	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, nil, args.Error(2)
	}

	txIDs, ok := args.Get(0).([]int64)
	if !ok {
		return nil, nil, mockTypeError("listConflictTxns ids")
	}

	hashes, ok := args.Get(1).([]chainhash.Hash)
	if !ok {
		return nil, nil, mockTypeError("listConflictTxns hashes")
	}

	return txIDs, hashes, args.Error(2)
}

// loadInvalidateTarget implements invalidateUnminedTxOps.
func (m *mockCreateTxOps) loadInvalidateTarget(ctx context.Context,
	walletID uint32,
	txHash chainhash.Hash) (invalidateUnminedTxTarget, error) {

	var zeroTarget invalidateUnminedTxTarget

	args := m.Called(ctx, walletID, txHash)
	if args.Get(0) == nil {
		return zeroTarget, args.Error(1)
	}

	target, ok := args.Get(0).(invalidateUnminedTxTarget)
	if !ok {
		return zeroTarget, mockTypeError("loadInvalidateTarget result")
	}

	return target, args.Error(1)
}

// listUnminedTxRecords implements invalidateUnminedTxOps.
func (m *mockCreateTxOps) listUnminedTxRecords(ctx context.Context,
	walletID int64) ([]unminedTxRecord, error) {

	args := m.Called(ctx, walletID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	records, ok := args.Get(0).([]unminedTxRecord)
	if !ok {
		return nil, mockTypeError("listUnminedTxRecords result")
	}

	return records, args.Error(1)
}

// clearSpentUtxos implements invalidateUnminedTxOps.
func (m *mockCreateTxOps) clearSpentUtxos(ctx context.Context, walletID int64,
	txID int64) error {

	args := m.Called(ctx, walletID, txID)

	return args.Error(0)
}

// markTxnsFailed implements invalidateUnminedTxOps.
func (m *mockCreateTxOps) markTxnsFailed(ctx context.Context, walletID int64,
	txIDs []int64) error {

	args := m.Called(ctx, walletID, txIDs)

	return args.Error(0)
}

// markTxnsReplaced implements createTxOps.
func (m *mockCreateTxOps) markTxnsReplaced(ctx context.Context, walletID int64,
	txIDs []int64) error {

	args := m.Called(ctx, walletID, txIDs)

	return args.Error(0)
}

// insertReplacementEdges implements createTxOps.
func (m *mockCreateTxOps) insertReplacementEdges(ctx context.Context,
	walletID int64, replacedTxIDs []int64, replacementTxID int64) error {

	args := m.Called(ctx, walletID, replacedTxIDs, replacementTxID)

	return args.Error(0)
}

// insert implements createTxOps.
func (m *mockCreateTxOps) insert(ctx context.Context,
	req createTxRequest) (int64, error) {

	args := m.Called(ctx, req)

	txID, ok := args.Get(0).(int64)
	if !ok {
		return 0, mockTypeError("insert result")
	}

	return txID, args.Error(1)
}

// insertCredits implements createTxOps.
func (m *mockCreateTxOps) insertCredits(ctx context.Context,
	req createTxRequest, txID int64) error {

	args := m.Called(ctx, req, txID)

	return args.Error(0)
}

// markInputsSpent implements createTxOps.
func (m *mockCreateTxOps) markInputsSpent(ctx context.Context,
	req createTxRequest, txID int64) error {

	args := m.Called(ctx, req, txID)

	return args.Error(0)
}

// mockUpdateTxOps is a mock implementation of updateTxOps.
type mockUpdateTxOps struct {
	mock.Mock
}

var _ updateTxOps = (*mockUpdateTxOps)(nil)

// loadIsCoinbase implements updateTxOps.
func (m *mockUpdateTxOps) loadIsCoinbase(ctx context.Context, walletID uint32,
	txHash chainhash.Hash) (bool, error) {

	args := m.Called(ctx, walletID, txHash)

	isCoinbase, ok := args.Get(0).(bool)
	if !ok {
		return false, mockTypeError("loadIsCoinbase result")
	}

	return isCoinbase, args.Error(1)
}

// prepareState implements updateTxOps.
func (m *mockUpdateTxOps) prepareState(ctx context.Context,
	state UpdateTxState) error {

	args := m.Called(ctx, state)

	return args.Error(0)
}

// updateLabel implements updateTxOps.
func (m *mockUpdateTxOps) updateLabel(ctx context.Context, walletID uint32,
	txHash chainhash.Hash, label string) error {

	args := m.Called(ctx, walletID, txHash, label)

	return args.Error(0)
}

// updateState implements updateTxOps.
func (m *mockUpdateTxOps) updateState(ctx context.Context, walletID uint32,
	txHash chainhash.Hash, state UpdateTxState) error {

	args := m.Called(ctx, walletID, txHash, state)

	return args.Error(0)
}

// testCreateTxRequest builds one valid normalized CreateTx request for the
// shared CreateTx orchestration tests.
func testCreateTxRequest(t *testing.T) createTxRequest {
	t.Helper()

	req, err := newCreateTxRequest(CreateTxParams{
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

	candidates := []unminedTxRecord{{
		id:   12,
		hash: chainhash.Hash{2},
		tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0},
		}}},
	}, {
		id:   13,
		hash: chainhash.Hash{3},
		tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{2}, Index: 0},
		}}},
	}}
	ops := &mockCreateTxOps{}
	t.Cleanup(func() { ops.AssertExpectations(t) })

	rootIDs := []int64{11, 12}
	rootHashes := []chainhash.Hash{{1}, {2}}

	ops.On("listUnminedTxRecords", mock.Anything, int64(7)).Return(
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
	req, err := newCreateTxRequest(CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
	})
	require.NoError(t, err)

	candidates := []unminedTxRecord{{
		id:   2,
		hash: childHash,
		tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: rootHash, Index: 0},
		}}},
	}, {
		id:   3,
		hash: grandchildHash,
		tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Hash: childHash, Index: 0},
		}}},
	}}

	ops := &mockCreateTxOps{}
	t.Cleanup(func() { ops.AssertExpectations(t) })

	ops.On("listConflictTxns", mock.Anything, req).Return(
		[]int64{1}, []chainhash.Hash{rootHash}, nil,
	).Once()

	ops.On("listUnminedTxRecords", mock.Anything, int64(7)).Return(
		candidates, nil).Once()

	ops.On("clearSpentUtxos", mock.Anything, int64(7), int64(1)).Return(nil).
		Once()

	ops.On("markTxnsReplaced", mock.Anything, int64(7), []int64{1}).Return(nil).
		Once()

	ops.On("insertReplacementEdges", mock.Anything, int64(7), []int64{1},
		int64(9)).Return(nil).Once()

	ops.On("clearSpentUtxos", mock.Anything, int64(7), int64(2)).Return(nil).
		Once()

	ops.On("clearSpentUtxos", mock.Anything, int64(7), int64(3)).Return(nil).
		Once()

	ops.On("markTxnsFailed", mock.Anything, int64(7), []int64{2, 3}).
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
	req, err := newCreateTxRequest(CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
	})
	require.NoError(t, err)

	ops := &mockCreateTxOps{}
	t.Cleanup(func() { ops.AssertExpectations(t) })

	ops.On("listConflictTxns", mock.Anything, req).Return(
		[]int64{1, 2},
		[]chainhash.Hash{rootAHash, rootBHash},
		nil,
	).Once()

	ops.On("listUnminedTxRecords", mock.Anything, int64(7)).Return(
		[]unminedTxRecord{{
			id:   2,
			hash: rootBHash,
			tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Hash: rootAHash, Index: 0},
			}}},
		}, {
			id:   3,
			hash: childHash,
			tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Hash: rootBHash, Index: 0},
			}}},
		}}, nil).Once()

	ops.On("clearSpentUtxos", mock.Anything, int64(7), int64(1)).Return(nil).
		Once()
	ops.On("clearSpentUtxos", mock.Anything, int64(7), int64(2)).Return(nil).
		Once()
	ops.On("markTxnsReplaced", mock.Anything, int64(7), []int64{1, 2}).Return(nil).
		Once()
	ops.On("insertReplacementEdges", mock.Anything, int64(7), []int64{1, 2},
		int64(9)).Return(nil).Once()
	ops.On("clearSpentUtxos", mock.Anything, int64(7), int64(3)).Return(nil).
		Once()
	ops.On("markTxnsFailed", mock.Anything, int64(7), []int64{3}).Return(nil).
		Once()

	err = handleTxConflicts(t.Context(), req, 9, ops)
	require.NoError(t, err)
}

// TestHandleTxConflictsNoDescendants verifies that the helper
// skips the descendant-failure batch when no dependent branch exists.
func TestHandleTxConflictsNoDescendants(t *testing.T) {
	t.Parallel()

	req, err := newCreateTxRequest(CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
	})
	require.NoError(t, err)

	ops := &mockCreateTxOps{}
	t.Cleanup(func() { ops.AssertExpectations(t) })

	ops.On("listConflictTxns", mock.Anything, req).Return(
		[]int64{1}, []chainhash.Hash{{1}}, nil,
	).Once()

	ops.On("listUnminedTxRecords", mock.Anything, int64(7)).Return(
		[]unminedTxRecord(nil), nil).Once()

	ops.On("clearSpentUtxos", mock.Anything, int64(7), int64(1)).Return(nil).
		Once()
	ops.On("markTxnsReplaced", mock.Anything, int64(7), []int64{1}).Return(nil).
		Once()
	ops.On("insertReplacementEdges", mock.Anything, int64(7), []int64{1},
		int64(9)).Return(nil).Once()

	err = handleTxConflicts(t.Context(), req, 9, ops)
	require.NoError(t, err)
}

// TestHandleTxConflictsMarkFailedError verifies that the helper records
// replacement edges before returning descendant failure errors.
func TestHandleTxConflictsMarkFailedError(t *testing.T) {
	t.Parallel()

	req, err := newCreateTxRequest(CreateTxParams{
		WalletID: 7,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(456, 0),
		Block:    testBlock(77),
		Status:   TxStatusPublished,
	})
	require.NoError(t, err)

	ops := &mockCreateTxOps{}
	t.Cleanup(func() { ops.AssertExpectations(t) })

	ops.On("listConflictTxns", mock.Anything, req).Return(
		[]int64{1}, []chainhash.Hash{{1}}, nil,
	).Once()

	ops.On("listUnminedTxRecords", mock.Anything, int64(7)).Return(
		[]unminedTxRecord{{
			id:   2,
			hash: chainhash.Hash{2},
			tx: &wire.MsgTx{TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{1},
					Index: 0,
				},
			}}},
		}}, nil).Once()

	ops.On("clearSpentUtxos", mock.Anything, int64(7), int64(1)).Return(nil).
		Once()
	ops.On("markTxnsReplaced", mock.Anything, int64(7), []int64{1}).Return(nil).
		Once()
	ops.On("insertReplacementEdges", mock.Anything, int64(7), []int64{1},
		int64(9)).Return(nil).Once()
	ops.On("clearSpentUtxos", mock.Anything, int64(7), int64(2)).Return(nil).
		Once()
	ops.On("markTxnsFailed", mock.Anything, int64(7), []int64{2}).Return(
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
	t.Cleanup(func() { ops.AssertExpectations(t) })

	ops.On("loadIsCoinbase", mock.Anything, uint32(5), chainhash.Hash{1}).
		Return(false, nil).Once()

	ops.On("prepareState", mock.Anything, UpdateTxState{
		Status: TxStatusPublished,
	}).Return(nil).Once()

	ops.On("updateLabel", mock.Anything, uint32(5), chainhash.Hash{1},
		label).Return(nil).Run(func(args mock.Arguments) {
		labelArg, ok := args.Get(3).(string)
		require.True(t, ok)
		updatedLabel = labelArg
	}).Once()

	ops.On("updateState", mock.Anything, uint32(5), chainhash.Hash{1},
		UpdateTxState{Status: TxStatusPublished}).Return(nil).Run(
		func(args mock.Arguments) {
			stateArg, ok := args.Get(3).(UpdateTxState)
			require.True(t, ok)
			updatedState = stateArg
		},
	).Once()

	// Act: Run updateTxWithOps against a stub backend adapter.
	err := updateTxWithOps(context.Background(), params, ops)
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
	t.Cleanup(func() { ops.AssertExpectations(t) })

	ops.On("loadIsCoinbase", mock.Anything, uint32(5), chainhash.Hash{1}).Return(
		false, nil).Once()

	err := updateTxWithOps(context.Background(), params, ops)
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
			t.Cleanup(func() { ops.AssertExpectations(t) })

			ops.On("loadIsCoinbase", mock.Anything, uint32(5), chainhash.Hash{1}).
				Return(test.isCoinbase, nil).Once()

			err := updateTxWithOps(context.Background(), params, ops)
			require.ErrorIs(t, err, ErrInvalidParam)
			require.ErrorIs(t, err, ErrInvalidStatus)
		})
	}
}
