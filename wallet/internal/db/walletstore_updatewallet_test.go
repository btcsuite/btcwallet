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

// TestCreateWalletParamsValidateAllowsWatchOnlyScriptSecrets verifies that
// watch-only wallets accept required script-encryption material without
// including spendable private material.
func TestCreateWalletParamsValidateAllowsWatchOnlyScriptSecrets(t *testing.T) {
	t.Parallel()

	params := CreateWalletParams{
		Name:                     "watch-only",
		IsWatchOnly:              true,
		MasterKeyPrivParams:      []byte{1, 2, 3},
		EncryptedCryptoScriptKey: []byte{4, 5, 6},
	}

	err := params.Validate()

	require.NoError(t, err)
}

// TestCreateWalletParamsValidateRejectsWatchOnlySpendableSecrets verifies that
// watch-only wallet creation still rejects private wallet material.
func TestCreateWalletParamsValidateRejectsWatchOnlySpendableSecrets(
	t *testing.T) {

	t.Parallel()

	tests := []struct {
		name   string
		params CreateWalletParams
	}{
		{
			name: "private crypto key",
			params: CreateWalletParams{
				Name:                     "watch-only",
				IsWatchOnly:              true,
				MasterKeyPrivParams:      []byte{1, 2, 3},
				EncryptedCryptoPrivKey:   []byte{1},
				EncryptedCryptoScriptKey: []byte{4, 5, 6},
			},
		},
		{
			name: "master HD private key",
			params: CreateWalletParams{
				Name:                     "watch-only",
				IsWatchOnly:              true,
				EncryptedMasterPrivKey:   []byte{1},
				MasterKeyPrivParams:      []byte{1, 2, 3},
				EncryptedCryptoScriptKey: []byte{4, 5, 6},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.params.Validate()

			require.ErrorIs(t, err, ErrWatchOnlyViolation)
		})
	}
}

// TestCreateWalletParamsValidateRejectsMissingRequiredSecrets verifies that
// wallet creation rejects missing fields required by the wallet_secrets schema.
func TestCreateWalletParamsValidateRejectsMissingRequiredSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		params      CreateWalletParams
		wantErr     error
		wantContain string
	}{
		{
			name: "missing master private parameters",
			params: CreateWalletParams{
				Name:                     "wallet",
				EncryptedCryptoScriptKey: []byte{4, 5, 6},
			},
			wantErr:     ErrMissingField,
			wantContain: "wallet \"wallet\" master private parameters",
		},
		{
			name: "missing encrypted script key",
			params: CreateWalletParams{
				Name:                "wallet",
				MasterKeyPrivParams: []byte{1, 2, 3},
			},
			wantErr:     ErrMissingField,
			wantContain: "wallet \"wallet\" encrypted script crypto key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.params.Validate()

			require.ErrorIs(t, err, test.wantErr)
			require.ErrorContains(t, err, test.wantContain)
		})
	}
}
