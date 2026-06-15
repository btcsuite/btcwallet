package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	// Test errors for CreateWalletWithOps ops testing.
	errTestCreateWallet = errors.New("create wallet")
	errTestInsertSecret = errors.New("insert secret")
	errTestSyncState    = errors.New("sync state")
)

// mockCreateWalletOps is a mock implementation of CreateWalletOps.
type mockCreateWalletOps struct {
	mock.Mock
}

// Ensure mockCreateWalletOps implements CreateWalletOps at compile time.
var _ CreateWalletOps = (*mockCreateWalletOps)(nil)

// CreateWallet implements CreateWalletOps.
func (m *mockCreateWalletOps) CreateWallet(ctx context.Context,
	params CreateWalletParams) (int64, error) {

	args := m.Called(ctx, params)

	walletID, ok := args.Get(0).(int64)
	if !ok {
		return 0, mockTypeError("CreateWallet result")
	}

	return walletID, args.Error(1)
}

// InsertWalletSecrets implements CreateWalletOps.
func (m *mockCreateWalletOps) InsertWalletSecrets(ctx context.Context,
	walletID int64, params CreateWalletParams) error {

	args := m.Called(ctx, walletID, params)
	return args.Error(0)
}

// InsertWalletSyncState implements CreateWalletOps.
func (m *mockCreateWalletOps) InsertWalletSyncState(ctx context.Context,
	walletID int64, birthday time.Time) error {

	args := m.Called(ctx, walletID, birthday)
	return args.Error(0)
}

// GetWalletByID implements CreateWalletOps.
func (m *mockCreateWalletOps) GetWalletByID(ctx context.Context,
	walletID int64) (*WalletInfo, error) {

	args := m.Called(ctx, walletID)

	info, ok := args.Get(0).(*WalletInfo)
	if !ok && args.Get(0) != nil {
		return nil, mockTypeError("GetWalletByID result")
	}

	return info, args.Error(1)
}

// TestCreateWalletParamsValidate verifies the store-level invariants on
// wallet creation params: a spendable wallet must carry an encrypted master
// HD private key, while a watch-only wallet must not carry private secret
// material.
func TestCreateWalletParamsValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		params     CreateWalletParams
		wantErr    error
		wantErrStr string
	}{
		{
			name: "spendable with master priv key",
			params: CreateWalletParams{
				Name:                   "spendable",
				IsWatchOnly:            false,
				EncryptedMasterPrivKey: []byte{0x01},
			},
		},
		{
			// The regression: a spendable wallet without the master
			// secret must be rejected before the row is written, so a
			// retry that lost the seed cannot commit a keyless wallet.
			name: "spendable without master priv key",
			params: CreateWalletParams{
				Name:        "spendable",
				IsWatchOnly: false,
			},
			wantErr:    ErrSpendableWalletNeedsMasterPrivKey,
			wantErrStr: "spendable",
		},
		{
			name: "watch-only without secrets",
			params: CreateWalletParams{
				Name:        "watch-only",
				IsWatchOnly: true,
			},
		},
		{
			name: "watch-only with master priv key",
			params: CreateWalletParams{
				Name:                   "watch-only",
				IsWatchOnly:            true,
				EncryptedMasterPrivKey: []byte{0x01},
			},
			wantErr:    ErrWatchOnlyViolation,
			wantErrStr: "watch-only",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.params.Validate()

			if tc.wantErr == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tc.wantErr)
			require.ErrorContains(t, err, tc.wantErrStr)
		})
	}
}

// TestCreateWalletWithOps verifies that the shared helper performs the
// post-validation transactional stages and returns the fetched wallet info.
func TestCreateWalletWithOps(t *testing.T) {
	t.Parallel()

	params := CreateWalletParams{
		Name:        "primary",
		IsWatchOnly: false,
	}
	expectedWalletID := int64(42)
	expectedWallet := &WalletInfo{ID: 42, Name: "primary"}

	ops := &mockCreateWalletOps{}
	t.Cleanup(
		func() {
			ops.AssertExpectations(t)
		},
	)

	// Arrange: Set up successful backend responses for all three stages.
	// The helper assumes validation has already been performed by the backend.
	createCall := ops.On("CreateWallet", mock.Anything, params).
		Return(expectedWalletID, nil).Once()
	secretCall := ops.On(
		"InsertWalletSecrets", mock.Anything, expectedWalletID, params,
	).Return(nil).Once()
	syncCall := ops.On(
		"InsertWalletSyncState", mock.Anything, expectedWalletID, mock.Anything,
	).Return(nil).Once()
	fetchCall := ops.On("GetWalletByID", mock.Anything, expectedWalletID).
		Return(expectedWallet, nil).Once()

	mock.InOrder(createCall, secretCall, syncCall, fetchCall)

	// Act: Call the shared helper with pre-validated params.
	ctx := t.Context()
	info, err := CreateWalletWithOps(ctx, params, ops)

	// Assert: The helper returns the fetched wallet info.
	require.NoError(t, err)
	require.Equal(t, expectedWallet, info)
}

// TestCreateWalletWithOpsSequencesStagesInOrder verifies that the shared helper
// calls the three transactional stages in the correct order: CreateWallet,
// InsertWalletSecrets, InsertWalletSyncState, then GetWalletByID.
func TestCreateWalletWithOpsSequencesStagesInOrder(t *testing.T) {
	t.Parallel()

	params := CreateWalletParams{
		Name:        "primary",
		IsWatchOnly: false,
	}
	expectedWalletID := int64(42)
	expectedWallet := &WalletInfo{ID: 42, Name: "primary"}

	ops := &mockCreateWalletOps{}
	t.Cleanup(
		func() {
			ops.AssertExpectations(t)
		},
	)

	// Verify strict call order: CreateWallet -> InsertWalletSecrets ->
	// InsertWalletSyncState -> GetWalletByID. The helper owns this sequencing
	// after validation has already been performed by the backend.
	createCall := ops.On("CreateWallet", mock.Anything, params).
		Return(expectedWalletID, nil).Once()
	secretCall := ops.On(
		"InsertWalletSecrets", mock.Anything, expectedWalletID, params,
	).Return(nil).Once()
	syncCall := ops.On(
		"InsertWalletSyncState", mock.Anything, expectedWalletID, mock.Anything,
	).Return(nil).Once()
	fetchCall := ops.On("GetWalletByID", mock.Anything, expectedWalletID).
		Return(expectedWallet, nil).Once()

	mock.InOrder(createCall, secretCall, syncCall, fetchCall)

	ctx := t.Context()
	info, err := CreateWalletWithOps(ctx, params, ops)

	require.NoError(t, err)
	require.Equal(t, expectedWallet, info)
}

// TestCreateWalletWithOpsPropagatesCreateError verifies that the shared helper
// wraps backend errors with stage context and short-circuits on early failures.
func TestCreateWalletWithOpsPropagatesCreateError(t *testing.T) {
	t.Parallel()

	params := CreateWalletParams{
		Name:        "primary",
		IsWatchOnly: false,
	}

	ops := &mockCreateWalletOps{}
	t.Cleanup(
		func() {
			ops.AssertExpectations(t)
		},
	)

	ops.On("CreateWallet", mock.Anything, params).Return(
		int64(0), errTestCreateWallet,
	).Once()

	info, err := CreateWalletWithOps(t.Context(), params, ops)

	require.Nil(t, info)
	require.ErrorIs(t, err, errTestCreateWallet)
	require.ErrorContains(t, err, "create wallet")

	// Verify that later stages were not called.
	ops.AssertNotCalled(t, "InsertWalletSecrets")
	ops.AssertNotCalled(t, "InsertWalletSyncState")
	ops.AssertNotCalled(t, "GetWalletByID")
}

// TestCreateWalletWithOpsPropagatesInsertSecretsError verifies that the shared
// helper wraps InsertWalletSecrets errors with stage context and short-circuits
// on failure, preventing later stages from running.
func TestCreateWalletWithOpsPropagatesInsertSecretsError(t *testing.T) {
	t.Parallel()

	params := CreateWalletParams{
		Name:        "primary",
		IsWatchOnly: false,
	}
	expectedWalletID := int64(42)

	ops := &mockCreateWalletOps{}
	t.Cleanup(
		func() {
			ops.AssertExpectations(t)
		},
	)

	// Arrange: CreateWallet succeeds, but InsertWalletSecrets fails.
	createCall := ops.On("CreateWallet", mock.Anything, params).
		Return(expectedWalletID, nil).Once()
	secretCall := ops.On(
		"InsertWalletSecrets", mock.Anything, expectedWalletID, params,
	).Return(errTestInsertSecret).Once()

	mock.InOrder(createCall, secretCall)

	// Act: Call the shared helper.
	ctx := t.Context()
	info, err := CreateWalletWithOps(ctx, params, ops)

	// Assert: Error is wrapped with stage context and later stages are skipped.
	require.Nil(t, info)
	require.ErrorIs(t, err, errTestInsertSecret)
	require.ErrorContains(t, err, "insert wallet secrets")

	// Verify that later stages were not called.
	ops.AssertNotCalled(t, "InsertWalletSyncState")
	ops.AssertNotCalled(t, "GetWalletByID")
}

// TestCreateWalletWithOpsPropagatesInsertSyncStateError verifies that the
// shared helper wraps InsertWalletSyncState errors with stage context and
// short-circuits on failure, preventing the fetch stage from running.
func TestCreateWalletWithOpsPropagatesInsertSyncStateError(t *testing.T) {
	t.Parallel()

	params := CreateWalletParams{
		Name:        "primary",
		IsWatchOnly: false,
	}
	expectedWalletID := int64(42)

	ops := &mockCreateWalletOps{}
	t.Cleanup(
		func() {
			ops.AssertExpectations(t)
		},
	)

	// Arrange: CreateWallet and InsertWalletSecrets succeed, but
	// InsertWalletSyncState fails.
	createCall := ops.On("CreateWallet", mock.Anything, params).
		Return(expectedWalletID, nil).Once()
	secretCall := ops.On(
		"InsertWalletSecrets", mock.Anything, expectedWalletID, params,
	).Return(nil).Once()
	syncCall := ops.On(
		"InsertWalletSyncState", mock.Anything, expectedWalletID, mock.Anything,
	).Return(errTestSyncState).Once()

	mock.InOrder(createCall, secretCall, syncCall)

	// Act: Call the shared helper.
	ctx := t.Context()
	info, err := CreateWalletWithOps(ctx, params, ops)

	// Assert: Error is wrapped with stage context and fetch is skipped.
	require.Nil(t, info)
	require.ErrorIs(t, err, errTestSyncState)
	require.ErrorContains(t, err, "insert wallet sync state")

	// Verify that the fetch stage was not called.
	ops.AssertNotCalled(t, "GetWalletByID")
}

// TestCreateWalletWithOpsPropagatesGetWalletError verifies that the shared
// helper wraps GetWalletByID errors with stage context and returns nil when
// the fetch stage fails.
func TestCreateWalletWithOpsPropagatesGetWalletError(t *testing.T) {
	t.Parallel()

	params := CreateWalletParams{
		Name:        "primary",
		IsWatchOnly: false,
	}
	expectedWalletID := int64(42)

	ops := &mockCreateWalletOps{}
	t.Cleanup(
		func() {
			ops.AssertExpectations(t)
		},
	)

	// Arrange: All write stages succeed, but GetWalletByID fails.
	createCall := ops.On("CreateWallet", mock.Anything, params).
		Return(expectedWalletID, nil).Once()
	secretCall := ops.On(
		"InsertWalletSecrets", mock.Anything, expectedWalletID, params,
	).Return(nil).Once()
	syncCall := ops.On(
		"InsertWalletSyncState", mock.Anything, expectedWalletID, mock.Anything,
	).Return(nil).Once()
	fetchCall := ops.On("GetWalletByID", mock.Anything, expectedWalletID).
		Return(nil, ErrWalletNotFound).Once()

	mock.InOrder(createCall, secretCall, syncCall, fetchCall)

	// Act: Call the shared helper.
	ctx := t.Context()
	info, err := CreateWalletWithOps(ctx, params, ops)

	// Assert: Error is wrapped with stage context and nil is returned.
	require.Nil(t, info)
	require.ErrorIs(t, err, ErrWalletNotFound)
	require.ErrorContains(t, err, "fetch created wallet")
}
