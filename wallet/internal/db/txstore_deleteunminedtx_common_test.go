package db

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var errDeleteMockRowsType = errors.New(
	"DeleteUnminedTransaction result is not int64",
)

// mockDeleteUnminedTxOps is a mock implementation of DeleteUnminedTxOps. It
// embeds the invalidation mock because both workflows share the discovery half
// of the contract, and adds only the row removal half.
type mockDeleteUnminedTxOps struct {
	mockInvalidateUnminedTxOps
}

// DeleteCreatedUtxos implements DeleteUnminedTxOps.
func (m *mockDeleteUnminedTxOps) DeleteCreatedUtxos(ctx context.Context,
	walletID uint32, txID int64) error {

	args := m.Called(ctx, walletID, txID)

	return args.Error(0)
}

// DeleteUnminedTransaction implements DeleteUnminedTxOps.
func (m *mockDeleteUnminedTxOps) DeleteUnminedTransaction(ctx context.Context,
	walletID uint32, txHash chainhash.Hash) (int64, error) {

	args := m.Called(ctx, walletID, txHash)

	rows, ok := args.Get(0).(int64)
	if !ok {
		return 0, errDeleteMockRowsType
	}

	return rows, args.Error(1)
}

// recordDeleteStep appends one workflow step to steps so a test can assert the
// order the branch was removed in.
func recordDeleteStep(steps *[]string, step string) func(mock.Arguments) {
	return func(_ mock.Arguments) {
		*steps = append(*steps, step)
	}
}

// TestDeleteUnminedTxWithOps verifies that the shared deletion workflow removes
// the descendants before the root, and that every member clears the spend edges
// it claimed before its own row is removed.
func TestDeleteUnminedTxWithOps(t *testing.T) {
	t.Parallel()

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

	var steps []string

	ops := &mockDeleteUnminedTxOps{}
	t.Cleanup(func() { ops.AssertExpectations(t) })

	ops.On("LoadUnminedTxTarget", mock.Anything, uint32(7), rootHash).Return(
		UnminedTxTarget{
			ID:     1,
			TxHash: rootHash,
			Status: TxStatusPublished,
		}, nil).Once()

	ops.On("ListUnminedTxRecords", mock.Anything, int64(7)).Return(
		candidates, nil).Once()

	members := []struct {
		id   int64
		hash chainhash.Hash
	}{
		{id: 3, hash: grandchildHash},
		{id: 2, hash: childHash},
		{id: 1, hash: rootHash},
	}

	for _, member := range members {
		ops.On("ClearSpentUtxos", mock.Anything, int64(7), member.id).
			Return(nil).
			Run(recordDeleteStep(
				&steps, fmt.Sprintf("clear:%d", member.id),
			)).Once()

		ops.On("DeleteCreatedUtxos", mock.Anything, uint32(7), member.id).
			Return(nil).
			Run(recordDeleteStep(
				&steps, fmt.Sprintf("outputs:%d", member.id),
			)).Once()

		ops.On("DeleteUnminedTransaction", mock.Anything, uint32(7),
			member.hash).
			Return(int64(1), nil).
			Run(recordDeleteStep(
				&steps, fmt.Sprintf("row:%d", member.id),
			)).Once()
	}

	err := DeleteUnminedTxWithOps(
		t.Context(),
		DeleteUnminedTxParams{WalletID: 7, Txid: rootHash},
		ops,
	)
	require.NoError(t, err)

	require.Equal(t, []string{
		"clear:3", "outputs:3", "row:3",
		"clear:2", "outputs:2", "row:2",
		"clear:1", "outputs:1", "row:1",
	}, steps)
}

// TestDeleteUnminedTxWithOpsRejectsConfirmed verifies that a confirmed root is
// refused with the delete workflow's own identity before any row is touched.
// The mock carries no removal expectations, so reaching one fails the test.
func TestDeleteUnminedTxWithOpsRejectsConfirmed(t *testing.T) {
	t.Parallel()

	rootHash := chainhash.Hash{4}

	ops := &mockDeleteUnminedTxOps{}
	t.Cleanup(func() { ops.AssertExpectations(t) })

	ops.On("LoadUnminedTxTarget", mock.Anything, uint32(9), rootHash).Return(
		UnminedTxTarget{
			ID:       5,
			TxHash:   rootHash,
			Status:   TxStatusPublished,
			HasBlock: true,
		}, nil).Once()

	err := DeleteUnminedTxWithOps(
		t.Context(),
		DeleteUnminedTxParams{WalletID: 9, Txid: rootHash},
		ops,
	)

	require.ErrorIs(t, err, ErrDeleteRequiresUnmined)
	require.NotErrorIs(t, err, ErrInvalidateTx)
}

// TestDeleteUnminedTxWithOpsMissingRow verifies that a row which disappears
// between discovery and removal is reported as a missing transaction rather
// than as a silent success.
func TestDeleteUnminedTxWithOpsMissingRow(t *testing.T) {
	t.Parallel()

	rootHash := chainhash.Hash{6}

	ops := &mockDeleteUnminedTxOps{}
	t.Cleanup(func() { ops.AssertExpectations(t) })

	ops.On("LoadUnminedTxTarget", mock.Anything, uint32(3), rootHash).Return(
		UnminedTxTarget{
			ID:     8,
			TxHash: rootHash,
			Status: TxStatusPending,
		}, nil).Once()

	ops.On("ListUnminedTxRecords", mock.Anything, int64(3)).Return(
		[]UnminedTxRecord(nil), nil).Once()

	ops.On("ClearSpentUtxos", mock.Anything, int64(3), int64(8)).
		Return(nil).Once()

	ops.On("DeleteCreatedUtxos", mock.Anything, uint32(3), int64(8)).
		Return(nil).Once()

	ops.On("DeleteUnminedTransaction", mock.Anything, uint32(3), rootHash).
		Return(int64(0), nil).Once()

	err := DeleteUnminedTxWithOps(
		t.Context(),
		DeleteUnminedTxParams{WalletID: 3, Txid: rootHash},
		ops,
	)

	require.ErrorIs(t, err, ErrTxNotFound)
}
