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

	errInvalidateMockLoadTargetType = errors.New(
		"LoadUnminedTxTarget result is not UnminedTxTarget",
	)

	errInvalidateMockListUnminedType = errors.New(
		"ListUnminedTxRecords result is not []UnminedTxRecord",
	)
)

// mockInvalidateUnminedTxOps is a mock implementation of
// InvalidateUnminedTxOps.
type mockInvalidateUnminedTxOps struct {
	mock.Mock
}

// LoadUnminedTxTarget implements UnminedBranchOps.
func (m *mockInvalidateUnminedTxOps) LoadUnminedTxTarget(ctx context.Context,
	walletID uint32,
	txHash chainhash.Hash) (InvalidateUnminedTxTarget, error) {

	args := m.Called(ctx, walletID, txHash)
	if args.Get(0) == nil {
		return InvalidateUnminedTxTarget{}, args.Error(1)
	}

	target, ok := args.Get(0).(InvalidateUnminedTxTarget)
	if !ok {
		return InvalidateUnminedTxTarget{},
			errInvalidateMockLoadTargetType
	}

	return target, args.Error(1)
}

// ListUnminedTxRecords implements InvalidateUnminedTxOps.
func (m *mockInvalidateUnminedTxOps) ListUnminedTxRecords(ctx context.Context,
	walletID int64) ([]UnminedTxRecord, error) {

	args := m.Called(ctx, walletID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	records, ok := args.Get(0).([]UnminedTxRecord)
	if !ok {
		return nil, errInvalidateMockListUnminedType
	}

	return records, args.Error(1)
}

// MarkTxnsFailed implements InvalidateUnminedTxOps.
func (m *mockInvalidateUnminedTxOps) MarkTxnsFailed(ctx context.Context,
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
		target  InvalidateUnminedTxTarget
		wantErr error
	}{
		{
			name: "pending root",
			target: InvalidateUnminedTxTarget{
				TxHash:   chainhash.Hash{1},
				Status:   TxStatusPending,
				HasBlock: false,
			},
		},
		{
			name: "published root",
			target: InvalidateUnminedTxTarget{
				TxHash:   chainhash.Hash{2},
				Status:   TxStatusPublished,
				HasBlock: false,
			},
		},
		{
			name: "confirmed root rejected",
			target: InvalidateUnminedTxTarget{
				TxHash:   chainhash.Hash{3},
				Status:   TxStatusPublished,
				HasBlock: true,
			},
			wantErr: ErrInvalidateTx,
		},
		{
			name: "failed root rejected",
			target: InvalidateUnminedTxTarget{
				TxHash: chainhash.Hash{4},
				Status: TxStatusFailed,
			},
			wantErr: ErrInvalidateTx,
		},
		{
			name: "coinbase root rejected",
			target: InvalidateUnminedTxTarget{
				TxHash:     chainhash.Hash{5},
				Status:     TxStatusPublished,
				IsCoinbase: true,
			},
			wantErr: ErrInvalidateTx,
		},
		{
			name: "orphaned root rejected",
			target: InvalidateUnminedTxTarget{
				TxHash: chainhash.Hash{6},
				Status: TxStatusOrphaned,
			},
			wantErr: ErrInvalidateTx,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := validateUnminedTxTarget(
				test.target, ErrInvalidateTx,
			)
			require.ErrorIs(t, err, test.wantErr)
		})
	}
}

// TestInvalidateUnminedTxWithOps verifies the shared invalidation workflow for
// one unmined root and its descendants.
func TestInvalidateUnminedTxWithOps(t *testing.T) {
	t.Parallel()

	// Arrange: Supply the retained branch snapshot and exact adapter outcomes
	// so cleanup checks every required status or deletion call once.

	rootHash := chainhash.Hash{1}
	childHash := chainhash.Hash{2}
	grandchildHash := chainhash.Hash{3}

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

	var failedIDs []int64

	ops := &mockInvalidateUnminedTxOps{}
	t.Cleanup(func() { ops.AssertExpectations(t) })

	ops.On("LoadUnminedTxTarget", mock.Anything, uint32(7), rootHash).Return(
		InvalidateUnminedTxTarget{
			ID:     1,
			TxHash: rootHash,
			Status: TxStatusPublished,
		}, nil).Once()

	ops.On("ListUnminedTxRecords", mock.Anything, int64(7)).Return(
		candidates, nil).Once()

	ops.On("MarkTxnsFailed", mock.Anything, int64(7), []int64{1, 2, 3}).Return(
		nil).Run(func(args mock.Arguments) {
		txIDs, ok := args.Get(2).([]int64)
		require.True(t, ok)

		failedIDs = append([]int64(nil), txIDs...)
	}).Once()

	// Act: Apply the branch operation to the prepared root and descendants.
	err := InvalidateUnminedTxWithOps(
		t.Context(),
		InvalidateUnminedTxParams{WalletID: 7, Txid: rootHash},
		ops,
	)
	require.NoError(t, err)

	// Assert: One status update invalidates the complete branch; input facts
	// remain retained instead of being cleared as a spend projection.
	require.Equal(t, []int64{1, 2, 3}, failedIDs)
}

// TestInvalidateUnminedTxWithOpsNoDescendants verifies that the shared helper
// still fails the root when no dependent branch exists.
func TestInvalidateUnminedTxWithOpsNoDescendants(t *testing.T) {
	t.Parallel()

	// Arrange: Supply the retained branch snapshot and exact adapter outcomes
	// so cleanup checks every required status or deletion call once.

	var failedIDs []int64

	ops := &mockInvalidateUnminedTxOps{}
	t.Cleanup(func() { ops.AssertExpectations(t) })

	ops.On("LoadUnminedTxTarget",
		mock.Anything, uint32(8), chainhash.Hash{9},
	).Return(
		InvalidateUnminedTxTarget{
			ID:     4,
			TxHash: chainhash.Hash{9},
			Status: TxStatusPending,
		}, nil).Once()

	ops.On("ListUnminedTxRecords", mock.Anything, int64(8)).Return(
		[]UnminedTxRecord(nil), nil).Once()

	ops.On("MarkTxnsFailed", mock.Anything, int64(8), []int64{4}).Return(
		nil).Run(func(args mock.Arguments) {
		txIDs, ok := args.Get(2).([]int64)
		require.True(t, ok)

		failedIDs = append([]int64(nil), txIDs...)
	}).Once()

	// Act: Apply the branch operation to the prepared root and descendants.
	err := InvalidateUnminedTxWithOps(
		t.Context(),
		InvalidateUnminedTxParams{WalletID: 8, Txid: chainhash.Hash{9}},
		ops,
	)
	// Assert: Only the root becomes Failed; no nonexistent descendant adds a
	// status write, and fixture cleanup verifies the required calls once.
	require.NoError(t, err)
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

		ops.On("LoadUnminedTxTarget",
			mock.Anything, uint32(8), chainhash.Hash{1}).Return(
			nil, errInvalidateCommonTest).Once()

		err := InvalidateUnminedTxWithOps(
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

		ops.On("LoadUnminedTxTarget",
			mock.Anything, uint32(8), chainhash.Hash{2}).Return(
			InvalidateUnminedTxTarget{
				ID:     5,
				TxHash: chainhash.Hash{2},
				Status: TxStatusPublished,
			}, nil).Once()

		ops.On("ListUnminedTxRecords", mock.Anything, int64(8)).Return(
			nil, errInvalidateCommonTest).Once()

		err := InvalidateUnminedTxWithOps(
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
