package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockUpdateWalletOps is a mock implementation of UpdateWalletOps.
type mockUpdateWalletOps struct {
	mock.Mock
}

// Ensure mockUpdateWalletOps implements UpdateWalletOps at compile time.
var _ UpdateWalletOps = (*mockUpdateWalletOps)(nil)

// EnsureBlock implements UpdateWalletOps.
func (m *mockUpdateWalletOps) EnsureBlock(ctx context.Context,
	block *Block) error {

	args := m.Called(ctx, block)
	return args.Error(0)
}

// UpdateWalletSyncState implements UpdateWalletOps.
func (m *mockUpdateWalletOps) UpdateWalletSyncState(ctx context.Context,
	params UpdateWalletParams) error {

	args := m.Called(ctx, params)
	return args.Error(0)
}

// TestUpdateWalletWithOps verifies that the shared helper owns the common
// wallet-update workflow and sequences block ensures before the sync update.
func TestUpdateWalletWithOps(t *testing.T) {
	t.Parallel()

	params := UpdateWalletParams{
		WalletID: 7,
	}
	syncedBlock := &Block{
		Height: 100,
	}
	params.SyncedTo = syncedBlock

	ops := &mockUpdateWalletOps{}
	t.Cleanup(
		func() {
			ops.AssertExpectations(t)
		},
	)

	// Verify call order: EnsureBlock for SyncedTo -> UpdateWalletSyncState.
	ensureCall := ops.On("EnsureBlock", mock.Anything, syncedBlock).
		Return(nil).Once()
	updateCall := ops.On("UpdateWalletSyncState", mock.Anything, params).
		Return(nil).Once()

	mock.InOrder(ensureCall, updateCall)

	ctx := t.Context()
	err := UpdateWalletWithOps(ctx, params, ops)

	require.NoError(t, err)
}

// TestUpdateWalletWithOpsEnsuresBlocksBeforeUpdate verifies that the shared
// helper ensures both synced and birthday blocks in the correct order before
// calling the backend update.
func TestUpdateWalletWithOpsEnsuresBlocksBeforeUpdate(t *testing.T) {
	t.Parallel()

	params := UpdateWalletParams{
		WalletID: 7,
	}
	syncedBlock := &Block{
		Height: 100,
	}
	birthdayBlock := &Block{
		Height: 50,
	}
	params.SyncedTo = syncedBlock
	params.BirthdayBlock = birthdayBlock

	ops := &mockUpdateWalletOps{}
	t.Cleanup(
		func() {
			ops.AssertExpectations(t)
		},
	)

	// Verify call order: EnsureBlock for SyncedTo -> EnsureBlock for
	// BirthdayBlock -> UpdateWalletSyncState.
	ensureSyncCall := ops.On("EnsureBlock", mock.Anything, syncedBlock).
		Return(nil).Once()
	ensureBirthdayCall := ops.On("EnsureBlock", mock.Anything, birthdayBlock).
		Return(nil).Once()
	updateCall := ops.On("UpdateWalletSyncState", mock.Anything, params).
		Return(nil).Once()

	mock.InOrder(ensureSyncCall, ensureBirthdayCall, updateCall)

	ctx := t.Context()
	err := UpdateWalletWithOps(ctx, params, ops)

	require.NoError(t, err)
}

// TestUpdateWalletWithOpsWalletNotFound verifies that the shared helper
// propagates wallet-not-found errors from the backend update stage.
func TestUpdateWalletWithOpsWalletNotFound(t *testing.T) {
	t.Parallel()

	params := UpdateWalletParams{
		WalletID: 7,
	}

	ops := &mockUpdateWalletOps{}
	t.Cleanup(
		func() {
			ops.AssertExpectations(t)
		},
	)

	ops.On("UpdateWalletSyncState", mock.Anything, params).Return(
		ErrWalletNotFound,
	).Once()

	ctx := t.Context()
	err := UpdateWalletWithOps(ctx, params, ops)

	require.ErrorIs(t, err, ErrWalletNotFound)
}
