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
	require.ErrorContains(t, err, "upsert wallet sync state")

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

// mockCreateWalletOps is a mock implementation of CreateWalletOps.
type mockCreateWalletOps struct {
	mock.Mock
}

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

// mockUpdateWalletOps is a mock implementation of UpdateWalletOps.
type mockUpdateWalletOps struct {
	mock.Mock
}

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

// mockUpdateWalletSecretsOps is a mock implementation of
// UpdateWalletSecretsOps.
type mockUpdateWalletSecretsOps struct {
	mock.Mock
}

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
