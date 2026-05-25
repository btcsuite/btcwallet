package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockUpdateWalletSecretsOps is a mock implementation of
// UpdateWalletSecretsOps.
type mockUpdateWalletSecretsOps struct {
	mock.Mock
}

// Ensure mockUpdateWalletSecretsOps implements UpdateWalletSecretsOps at
// compile time.
var _ UpdateWalletSecretsOps = (*mockUpdateWalletSecretsOps)(nil)

// WalletWatchOnly implements UpdateWalletSecretsOps.
func (m *mockUpdateWalletSecretsOps) WalletWatchOnly(ctx context.Context,
	walletID uint32) (bool, error) {

	args := m.Called(ctx, walletID)

	isWatchOnly, ok := args.Get(0).(bool)
	if !ok {
		return false, mockTypeError("WalletWatchOnly result")
	}

	return isWatchOnly, args.Error(1)
}

// UpdateWalletSecrets implements UpdateWalletSecretsOps.
func (m *mockUpdateWalletSecretsOps) UpdateWalletSecrets(ctx context.Context,
	params UpdateWalletSecretsParams) error {

	args := m.Called(ctx, params)
	return args.Error(0)
}

// TestUpdateWalletSecretsWithOps verifies that the shared helper owns the
// common wallet-secrets-update workflow and validates watch-only constraints
// before the backend update.
func TestUpdateWalletSecretsWithOps(t *testing.T) {
	t.Parallel()

	params := UpdateWalletSecretsParams{
		WalletID: 7,
	}

	ops := &mockUpdateWalletSecretsOps{}
	t.Cleanup(
		func() {
			ops.AssertExpectations(t)
		},
	)

	// Verify call order: WalletWatchOnly -> UpdateWalletSecrets.
	watchOnlyCall := ops.On("WalletWatchOnly", mock.Anything, uint32(7)).
		Return(false, nil).Once()
	updateCall := ops.On("UpdateWalletSecrets", mock.Anything, params).
		Return(nil).Once()

	mock.InOrder(watchOnlyCall, updateCall)

	ctx := t.Context()
	err := UpdateWalletSecretsWithOps(ctx, params, ops)

	require.NoError(t, err)
}

// TestUpdateWalletSecretsWithOpsWalletNotFound verifies that the shared helper
// propagates wallet-not-found errors from the backend load stage.
func TestUpdateWalletSecretsWithOpsWalletNotFound(t *testing.T) {
	t.Parallel()

	params := UpdateWalletSecretsParams{
		WalletID: 7,
	}

	ops := &mockUpdateWalletSecretsOps{}
	t.Cleanup(
		func() {
			ops.AssertExpectations(t)
		},
	)

	ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
		false, ErrWalletNotFound,
	).Once()

	ctx := t.Context()
	err := UpdateWalletSecretsWithOps(ctx, params, ops)

	require.ErrorIs(t, err, ErrWalletNotFound)

	// Verify that the update was not called.
	ops.AssertNotCalled(t, "UpdateWalletSecrets")
}

// TestUpdateWalletSecretsWithOpsRejectsWatchOnlyPrivateSecrets verifies that
// the shared helper validates watch-only constraints before the backend update.
func TestUpdateWalletSecretsWithOpsRejectsWatchOnlyPrivateSecrets(
	t *testing.T) {

	t.Parallel()

	params := UpdateWalletSecretsParams{
		WalletID:                 7,
		EncryptedMasterHdPrivKey: []byte{1, 2, 3},
	}

	ops := &mockUpdateWalletSecretsOps{}
	t.Cleanup(
		func() {
			ops.AssertExpectations(t)
		},
	)

	// Wallet is watch-only, so private secrets should be rejected.
	ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
		true, nil,
	).Once()

	ctx := t.Context()
	err := UpdateWalletSecretsWithOps(ctx, params, ops)

	require.ErrorIs(t, err, ErrWatchOnlyViolation)

	// Verify that the update was not called.
	ops.AssertNotCalled(t, "UpdateWalletSecrets")
}
