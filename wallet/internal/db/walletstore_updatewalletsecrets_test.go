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
		WalletID:                 7,
		MasterPrivParams:         []byte{1, 2, 3},
		EncryptedCryptoPrivKey:   []byte{4, 5, 6},
		EncryptedCryptoScriptKey: []byte{4, 5, 6},
		EncryptedMasterHdPrivKey: []byte{7, 8, 9},
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
		MasterPrivParams:         []byte{1, 2, 3},
		EncryptedCryptoScriptKey: []byte{4, 5, 6},
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

// TestUpdateWalletSecretsParamsValidateAllowsWatchOnlyScriptSecrets verifies
// that watch-only updates may rotate passphrase parameters for script-only
// encryption without admitting spendable private material.
func TestUpdateWalletSecretsParamsValidateAllowsWatchOnlyScriptSecrets(
	t *testing.T) {

	t.Parallel()

	params := UpdateWalletSecretsParams{
		WalletID:                 7,
		MasterPrivParams:         []byte{1, 2, 3},
		EncryptedCryptoScriptKey: []byte{4, 5, 6},
	}

	err := params.Validate(true)

	require.NoError(t, err)
}

// TestUpdateWalletSecretsParamsValidateRejectsWatchOnlySpendableSecrets
// verifies that watch-only updates still reject private wallet material.
func TestUpdateWalletSecretsParamsValidateRejectsWatchOnlySpendableSecrets(
	t *testing.T) {

	t.Parallel()

	tests := []struct {
		name   string
		params UpdateWalletSecretsParams
	}{
		{
			name: "private crypto key",
			params: UpdateWalletSecretsParams{
				WalletID:                 7,
				MasterPrivParams:         []byte{1, 2, 3},
				EncryptedCryptoPrivKey:   []byte{1},
				EncryptedCryptoScriptKey: []byte{4, 5, 6},
			},
		},
		{
			name: "master HD private key",
			params: UpdateWalletSecretsParams{
				WalletID:                 7,
				MasterPrivParams:         []byte{1, 2, 3},
				EncryptedCryptoScriptKey: []byte{4, 5, 6},
				EncryptedMasterHdPrivKey: []byte{1},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.params.Validate(true)

			require.ErrorIs(t, err, ErrWatchOnlyViolation)
		})
	}
}

// TestUpdateWalletSecretsParamsValidateRejectsMissingRequiredSecrets verifies
// that updates reject missing fields required by the wallet_secrets schema.
func TestUpdateWalletSecretsParamsValidateRejectsMissingRequiredSecrets(
	t *testing.T) {

	t.Parallel()

	tests := []struct {
		name        string
		params      UpdateWalletSecretsParams
		wantErr     error
		wantContain string
	}{
		{
			name: "missing master private parameters",
			params: UpdateWalletSecretsParams{
				WalletID:                 7,
				EncryptedCryptoScriptKey: []byte{4, 5, 6},
			},
			wantErr:     ErrMissingField,
			wantContain: "wallet 7 master private parameters",
		},
		{
			name: "missing encrypted script key",
			params: UpdateWalletSecretsParams{
				WalletID:         7,
				MasterPrivParams: []byte{1, 2, 3},
			},
			wantErr:     ErrMissingField,
			wantContain: "wallet 7 encrypted script crypto key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.params.Validate(false)

			require.ErrorIs(t, err, test.wantErr)
			require.ErrorContains(t, err, test.wantContain)
		})
	}
}

// TestUpdateWalletSecretsParamsValidateRejectsSpendableIncompleteSecrets
// verifies that spendable wallet secret updates require private material.
func TestUpdateWalletSecretsParamsValidateRejectsSpendableIncompleteSecrets(
	t *testing.T) {

	t.Parallel()

	tests := []struct {
		name        string
		params      UpdateWalletSecretsParams
		wantErr     error
		wantContain string
	}{
		{
			name: "missing encrypted private crypto key",
			params: UpdateWalletSecretsParams{
				WalletID:                 7,
				MasterPrivParams:         []byte{1, 2, 3},
				EncryptedCryptoScriptKey: []byte{4, 5, 6},
				EncryptedMasterHdPrivKey: []byte{7, 8, 9},
			},
			wantErr:     ErrMissingField,
			wantContain: "wallet 7 private crypto key",
		},
		{
			name: "missing encrypted master HD private key",
			params: UpdateWalletSecretsParams{
				WalletID:                 7,
				MasterPrivParams:         []byte{1, 2, 3},
				EncryptedCryptoPrivKey:   []byte{4, 5, 6},
				EncryptedCryptoScriptKey: []byte{7, 8, 9},
			},
			wantErr:     ErrMissingField,
			wantContain: "wallet 7 master HD private key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.params.Validate(false)

			require.ErrorIs(t, err, test.wantErr)
			require.ErrorContains(t, err, test.wantContain)
		})
	}
}
