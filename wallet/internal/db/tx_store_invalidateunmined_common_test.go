package db

import (
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	errInvalidateCommonTest = errors.New("invalidate common test")

	errInvalidateMockLoadInvalidateTargetType = errors.New(
		"loadInvalidateTarget result is not invalidateUnminedTxTarget",
	)

	errInvalidateMockListUnminedType = errors.New(
		"listUnminedTxRecords result is not []unminedTxRecord",
	)
)

// mockInvalidateUnminedTxOps is a mock implementation of
// invalidateUnminedTxOps.
type mockInvalidateUnminedTxOps struct {
	mock.Mock
}

// loadInvalidateTarget implements invalidateUnminedTxOps.
func (m *mockInvalidateUnminedTxOps) loadInvalidateTarget(ctx context.Context,
	walletID uint32,
	txHash chainhash.Hash) (invalidateUnminedTxTarget, error) {

	args := m.Called(ctx, walletID, txHash)
	if args.Get(0) == nil {
		return invalidateUnminedTxTarget{}, args.Error(1)
	}

	target, ok := args.Get(0).(invalidateUnminedTxTarget)
	if !ok {
		return invalidateUnminedTxTarget{},
			errInvalidateMockLoadInvalidateTargetType
	}

	return target, args.Error(1)
}

// listUnminedTxRecords implements invalidateUnminedTxOps.
func (m *mockInvalidateUnminedTxOps) listUnminedTxRecords(ctx context.Context,
	walletID int64) ([]unminedTxRecord, error) {

	args := m.Called(ctx, walletID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	records, ok := args.Get(0).([]unminedTxRecord)
	if !ok {
		return nil, errInvalidateMockListUnminedType
	}

	return records, args.Error(1)
}

// clearSpentUtxos implements invalidateUnminedTxOps.
func (m *mockInvalidateUnminedTxOps) clearSpentUtxos(ctx context.Context,
	walletID int64, txID int64) error {

	args := m.Called(ctx, walletID, txID)

	return args.Error(0)
}

// markTxnsFailed implements invalidateUnminedTxOps.
func (m *mockInvalidateUnminedTxOps) markTxnsFailed(ctx context.Context,
	walletID int64, txIDs []int64) error {

	args := m.Called(ctx, walletID, txIDs)

	return args.Error(0)
}

// TestValidateInvalidateUnminedTxTarget verifies the root-state validation for
// InvalidateUnminedTx.
func TestValidateInvalidateUnminedTxTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		target  invalidateUnminedTxTarget
		wantErr error
	}{
		{
			name: "pending root",
			target: invalidateUnminedTxTarget{
				txHash:   chainhash.Hash{1},
				status:   TxStatusPending,
				hasBlock: false,
			},
		},
		{
			name: "published root",
			target: invalidateUnminedTxTarget{
				txHash:   chainhash.Hash{2},
				status:   TxStatusPublished,
				hasBlock: false,
			},
		},
		{
			name: "confirmed root rejected",
			target: invalidateUnminedTxTarget{
				txHash:   chainhash.Hash{3},
				status:   TxStatusPublished,
				hasBlock: true,
			},
			wantErr: ErrInvalidateTx,
		},
		{
			name: "failed root rejected",
			target: invalidateUnminedTxTarget{
				txHash: chainhash.Hash{4},
				status: TxStatusFailed,
			},
			wantErr: ErrInvalidateTx,
		},
		{
			name: "coinbase root rejected",
			target: invalidateUnminedTxTarget{
				txHash:     chainhash.Hash{5},
				status:     TxStatusPublished,
				isCoinbase: true,
			},
			wantErr: ErrInvalidateTx,
		},
		{
			name: "orphaned root rejected",
			target: invalidateUnminedTxTarget{
				txHash: chainhash.Hash{6},
				status: TxStatusOrphaned,
			},
			wantErr: ErrInvalidateTx,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := validateUnminedTxTarget(test.target)
			require.ErrorIs(t, err, test.wantErr)
		})
	}
}

// TestInvalidateUnminedTxWithOps verifies the shared invalidation workflow for
// one unmined root and its descendants.
func TestInvalidateUnminedTxWithOps(t *testing.T) {
	t.Parallel()

	rootHash := chainhash.Hash{1}
	childHash := chainhash.Hash{2}
	grandchildHash := chainhash.Hash{3}

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

	var (
		cleared   []int64
		failedIDs []int64
	)

	ops := &mockInvalidateUnminedTxOps{}
	t.Cleanup(func() { ops.AssertExpectations(t) })

	ops.On("loadInvalidateTarget", mock.Anything, uint32(7), rootHash).Return(
		invalidateUnminedTxTarget{
			id:     1,
			txHash: rootHash,
			status: TxStatusPublished,
		}, nil).Once()

	ops.On("listUnminedTxRecords", mock.Anything, int64(7)).Return(
		candidates, nil).Once()

	ops.On("clearSpentUtxos", mock.Anything, int64(7), int64(1)).Return(
		nil).Run(func(args mock.Arguments) {
		txID, ok := args.Get(2).(int64)
		require.True(t, ok)
		cleared = append(cleared, txID)
	}).Once()

	ops.On("clearSpentUtxos", mock.Anything, int64(7), int64(2)).Return(
		nil).Run(func(args mock.Arguments) {
		txID, ok := args.Get(2).(int64)
		require.True(t, ok)
		cleared = append(cleared, txID)
	}).Once()

	ops.On("clearSpentUtxos", mock.Anything, int64(7), int64(3)).Return(
		nil).Run(func(args mock.Arguments) {
		txID, ok := args.Get(2).(int64)
		require.True(t, ok)
		cleared = append(cleared, txID)
	}).Once()

	ops.On("markTxnsFailed", mock.Anything, int64(7), []int64{1, 2, 3}).Return(
		nil).Run(func(args mock.Arguments) {
		txIDs, ok := args.Get(2).([]int64)
		require.True(t, ok)
		failedIDs = append([]int64(nil), txIDs...)
	}).Once()

	err := invalidateUnminedTxWithOps(
		t.Context(),
		InvalidateUnminedTxParams{WalletID: 7, Txid: rootHash},
		ops,
	)
	require.NoError(t, err)

	// The root spend is cleared first, then each discovered descendant spend is
	// cleared before the whole branch is marked failed in one batch update.
	require.Equal(t, []int64{1, 2, 3}, cleared)
	require.Equal(t, []int64{1, 2, 3}, failedIDs)
}

// TestInvalidateUnminedTxWithOpsNoDescendants verifies that the shared helper
// still clears and fails the root when no dependent branch exists.
func TestInvalidateUnminedTxWithOpsNoDescendants(t *testing.T) {
	t.Parallel()

	var (
		cleared   []int64
		failedIDs []int64
	)

	ops := &mockInvalidateUnminedTxOps{}
	t.Cleanup(func() { ops.AssertExpectations(t) })

	ops.On("loadInvalidateTarget",
		mock.Anything, uint32(8), chainhash.Hash{9},
	).Return(
		invalidateUnminedTxTarget{
			id:     4,
			txHash: chainhash.Hash{9},
			status: TxStatusPending,
		}, nil).Once()

	ops.On("listUnminedTxRecords", mock.Anything, int64(8)).Return(
		[]unminedTxRecord(nil), nil).Once()

	ops.On("clearSpentUtxos", mock.Anything, int64(8), int64(4)).Return(
		nil).Run(func(args mock.Arguments) {
		txID, ok := args.Get(2).(int64)
		require.True(t, ok)
		cleared = append(cleared, txID)
	}).Once()

	ops.On("markTxnsFailed", mock.Anything, int64(8), []int64{4}).Return(
		nil).Run(func(args mock.Arguments) {
		txIDs, ok := args.Get(2).([]int64)
		require.True(t, ok)
		failedIDs = append([]int64(nil), txIDs...)
	}).Once()

	err := invalidateUnminedTxWithOps(
		t.Context(),
		InvalidateUnminedTxParams{WalletID: 8, Txid: chainhash.Hash{9}},
		ops,
	)
	require.NoError(t, err)
	require.Equal(t, []int64{4}, cleared)
	require.Equal(t, []int64{4}, failedIDs)
}

// TestInvalidateUnminedTxWithOpsErrors verifies that the shared helper returns
// load and graph-discovery errors before mutating any rows.
func TestInvalidateUnminedTxWithOpsErrors(t *testing.T) {
	t.Parallel()

	t.Run("load target", func(t *testing.T) {
		t.Parallel()

		ops := &mockInvalidateUnminedTxOps{}
		t.Cleanup(func() { ops.AssertExpectations(t) })

		ops.On("loadInvalidateTarget",
			mock.Anything, uint32(8), chainhash.Hash{1}).Return(
			nil, errInvalidateCommonTest).Once()

		err := invalidateUnminedTxWithOps(
			t.Context(),
			InvalidateUnminedTxParams{
				WalletID: 8,
				Txid:     chainhash.Hash{1},
			},
			ops,
		)
		require.ErrorIs(t, err, errInvalidateCommonTest)
		require.ErrorContains(t, err, "load invalidate tx target")
	})

	t.Run("list descendants", func(t *testing.T) {
		t.Parallel()

		ops := &mockInvalidateUnminedTxOps{}
		t.Cleanup(func() { ops.AssertExpectations(t) })

		ops.On("loadInvalidateTarget",
			mock.Anything, uint32(8), chainhash.Hash{2}).Return(
			invalidateUnminedTxTarget{
				id:     5,
				txHash: chainhash.Hash{2},
				status: TxStatusPublished,
			}, nil).Once()

		ops.On("listUnminedTxRecords", mock.Anything, int64(8)).Return(
			nil, errInvalidateCommonTest).Once()

		err := invalidateUnminedTxWithOps(
			t.Context(),
			InvalidateUnminedTxParams{
				WalletID: 8,
				Txid:     chainhash.Hash{2}},
			ops,
		)
		require.ErrorIs(t, err, errInvalidateCommonTest)
		require.ErrorContains(t, err, "list unmined invalidation txns")
	})
}
