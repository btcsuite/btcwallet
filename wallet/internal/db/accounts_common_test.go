package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	// Test errors for CreateDerivedAccount ops testing.
	errTestWallet = errors.New("wallet")
	errTestScope  = errors.New("scope")
	errTestBoom   = errors.New("boom")
)

// TestCreateDerivedAccountParamsValidate verifies derived account creation
// validation rejects missing names.
func TestCreateDerivedAccountParamsValidate(t *testing.T) {
	t.Parallel()

	err := (&CreateDerivedAccountParams{Name: "default"}).Validate()
	require.NoError(t, err)

	err = (&CreateDerivedAccountParams{}).Validate()
	require.ErrorIs(t, err, ErrMissingAccountName)
}

// TestCreateImportedAccountParamsValidate verifies imported account creation
// validation rejects missing names and public keys.
func TestCreateImportedAccountParamsValidate(t *testing.T) {
	t.Parallel()

	err := (&CreateImportedAccountParams{
		Name:      "imported",
		PublicKey: []byte{1},
	}).ValidateBasic()
	require.NoError(t, err)

	err = (&CreateImportedAccountParams{
		PublicKey: []byte{1},
	}).ValidateBasic()
	require.ErrorIs(t, err, ErrMissingAccountName)

	err = (&CreateImportedAccountParams{Name: "imported"}).ValidateBasic()
	require.ErrorIs(t, err, ErrMissingAccountPublicKey)
}

// TestGetAccountQueryValidate verifies account lookups must use exactly one
// account selector.
func TestGetAccountQueryValidate(t *testing.T) {
	t.Parallel()

	name := "default"
	accountNumber := uint32(7)

	tests := []struct {
		name    string
		query   GetAccountQuery
		wantErr error
	}{
		{
			name:  "name selector",
			query: GetAccountQuery{Name: &name},
		},
		{
			name:  "number selector",
			query: GetAccountQuery{AccountNumber: &accountNumber},
		},
		{
			name:    "no selector",
			query:   GetAccountQuery{},
			wantErr: ErrInvalidAccountQuery,
		},
		{
			name: "both selectors",
			query: GetAccountQuery{
				Name:          &name,
				AccountNumber: &accountNumber,
			},
			wantErr: ErrInvalidAccountQuery,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.query.Validate()
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}

// TestRenameAccountParamsValidate verifies account renames must include a new
// name and exactly one account selector.
func TestRenameAccountParamsValidate(t *testing.T) {
	t.Parallel()

	accountNumber := uint32(7)

	tests := []struct {
		name    string
		params  RenameAccountParams
		wantErr error
	}{
		{
			name: "old name selector",
			params: RenameAccountParams{
				OldName: "default",
				NewName: "renamed",
			},
		},
		{
			name: "account number selector",
			params: RenameAccountParams{
				AccountNumber: &accountNumber,
				NewName:       "renamed",
			},
		},
		{
			name: "missing new name",
			params: RenameAccountParams{
				OldName: "default",
			},
			wantErr: ErrMissingAccountName,
		},
		{
			name: "no selector",
			params: RenameAccountParams{
				NewName: "renamed",
			},
			wantErr: ErrInvalidAccountQuery,
		},
		{
			name: "both selectors",
			params: RenameAccountParams{
				OldName:       "default",
				AccountNumber: &accountNumber,
				NewName:       "renamed",
			},
			wantErr: ErrInvalidAccountQuery,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.params.Validate()
			require.ErrorIs(t, err, test.wantErr)
		})
	}
}

// TestCreateDerivedAccountWithOps verifies that the shared helper owns the
// common derived-account workflow and returns the normalized AccountInfo.
func TestCreateDerivedAccountWithOps(t *testing.T) {
	t.Parallel()

	params := CreateDerivedAccountParams{
		WalletID: 7,
		Scope: KeyScope{
			Purpose: 49,
			Coin:    0,
		},
		Name: "savings",
	}
	createdAt := time.Unix(123, 0)
	expectedRow := CreateDerivedAccountRow{
		AccountNumber: sql.NullInt64{Int64: 12, Valid: true},
		CreatedAt:     createdAt,
	}

	ops := &mockCreateDerivedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	// Verify call order: WalletWatchOnly -> EnsureScope ->
	// AllocateAccountNumber -> CreateDerivedAccount.
	walletCall := ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
		true, nil,
	).Once()
	ensureScopeCall := ops.On(
		"EnsureScope", mock.Anything, uint32(7), params.Scope,
	).Return(int64(11), nil).Once()
	allocateCall := ops.On(
		"AllocateAccountNumber", mock.Anything, int64(11),
	).Return(int64(12), nil).Once()
	createCall := ops.On(
		"CreateDerivedAccount", mock.Anything, int64(11), int64(12), "savings",
	).Return(expectedRow, nil).Once()

	mock.InOrder(walletCall, ensureScopeCall, allocateCall, createCall)

	ctx := t.Context()
	info, err := CreateDerivedAccountWithOps(ctx, params, ops)

	require.NoError(t, err)
	require.Equal(t, uint32(12), info.AccountNumber)
	require.Equal(t, params.Name, info.AccountName)
	require.Equal(t, DerivedAccount, info.Origin)
	require.True(t, info.IsWatchOnly)
	require.Equal(t, createdAt, info.CreatedAt)
	require.Equal(t, params.Scope, info.KeyScope)
}

// TestCreateDerivedAccountWithOpsRejectsInvalidParams verifies that the shared
// helper validates the public request before any backend step runs.
func TestCreateDerivedAccountWithOpsRejectsInvalidParams(t *testing.T) {
	t.Parallel()

	ops := &mockCreateDerivedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	// Pass empty params (missing Name). No backend methods should be called.
	info, err := CreateDerivedAccountWithOps(
		t.Context(), CreateDerivedAccountParams{}, ops,
	)

	require.Nil(t, info)
	require.ErrorIs(t, err, ErrMissingAccountName)

	// Explicitly assert zero calls for each backend method.
	ops.AssertNotCalled(t, "WalletWatchOnly")
	ops.AssertNotCalled(t, "EnsureScope")
	ops.AssertNotCalled(t, "AllocateAccountNumber")
	ops.AssertNotCalled(t, "CreateDerivedAccount")
}

// TestCreateDerivedAccountWithOpsNilAccountNumber verifies that the shared
// helper rejects a nil account number returned from the backend.
func TestCreateDerivedAccountWithOpsNilAccountNumber(t *testing.T) {
	t.Parallel()

	ops := &mockCreateDerivedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
		false, nil,
	).Once()
	ops.On(
		"EnsureScope", mock.Anything, uint32(7), KeyScope{
			Purpose: 49,
			Coin:    0,
		},
	).Return(int64(8), nil).Once()
	ops.On("AllocateAccountNumber", mock.Anything, int64(8)).Return(
		int64(9), nil,
	).Once()
	ops.On(
		"CreateDerivedAccount", mock.Anything, int64(8), int64(9), "savings",
	).Return(
		CreateDerivedAccountRow{
			CreatedAt: time.Unix(456, 0),
		}, nil,
	).Once()

	info, err := CreateDerivedAccountWithOps(
		t.Context(), testCreateDerivedAccountParams(), ops,
	)

	require.Nil(t, info)
	require.ErrorIs(t, err, ErrNilDBAccountNumber)
}

// TestCreateDerivedAccountWithOpsMaxAccountNumber verifies that the shared
// helper preserves the existing max-account-number error mapping.
func TestCreateDerivedAccountWithOpsMaxAccountNumber(t *testing.T) {
	t.Parallel()

	ops := &mockCreateDerivedAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
		false, nil,
	).Once()
	ops.On(
		"EnsureScope", mock.Anything, uint32(7), KeyScope{
			Purpose: 49,
			Coin:    0,
		},
	).Return(int64(8), nil).Once()
	ops.On("AllocateAccountNumber", mock.Anything, int64(8)).Return(
		int64(^uint32(0))+1, nil,
	).Once()
	ops.On(
		"CreateDerivedAccount", mock.Anything, int64(8), int64(^uint32(0))+1,
		"savings",
	).Return(
		CreateDerivedAccountRow{
			AccountNumber: sql.NullInt64{
				Int64: int64(^uint32(0)) + 1,
				Valid: true,
			},
			CreatedAt: time.Unix(789, 0),
		}, nil,
	).Once()

	info, err := CreateDerivedAccountWithOps(
		t.Context(), testCreateDerivedAccountParams(), ops,
	)

	require.Nil(t, info)
	require.ErrorIs(t, err, ErrMaxAccountNumberReached)
	require.ErrorContains(t, err, "casting overflow")
}

// TestCreateDerivedAccountWithOpsWrapsStageErrors verifies that the shared
// helper keeps stage-specific error context around backend failures and
// short-circuits on early errors.
func TestCreateDerivedAccountWithOpsWrapsStageErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		setupOps        func() *mockCreateDerivedAccountOps
		wantErr         error
		wantWrappedText string
	}{
		{
			name: "wallet watch only",
			setupOps: func() *mockCreateDerivedAccountOps {
				ops := &mockCreateDerivedAccountOps{}
				ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
					false, errTestWallet,
				).Once()

				return ops
			},
			wantErr: errTestWallet,
		},
		{
			name: "ensure scope",
			setupOps: func() *mockCreateDerivedAccountOps {
				ops := &mockCreateDerivedAccountOps{}
				ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
					false, nil,
				).Once()
				ops.On(
					"EnsureScope", mock.Anything, uint32(7), KeyScope{
						Purpose: 49,
						Coin:    0,
					},
				).Return(int64(0), errTestScope).Once()

				return ops
			},
			wantErr: errTestScope,
		},
		{
			name: "allocate account number",
			setupOps: func() *mockCreateDerivedAccountOps {
				ops := &mockCreateDerivedAccountOps{}
				ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
					false, nil,
				).Once()
				ops.On(
					"EnsureScope", mock.Anything, uint32(7), KeyScope{
						Purpose: 49,
						Coin:    0,
					},
				).Return(int64(8), nil).Once()
				ops.On("AllocateAccountNumber", mock.Anything, int64(8)).Return(
					int64(0), errTestBoom,
				).Once()

				return ops
			},
			wantErr:         errTestBoom,
			wantWrappedText: "allocate account number: boom",
		},
		{
			name: "create account",
			setupOps: func() *mockCreateDerivedAccountOps {
				ops := &mockCreateDerivedAccountOps{}
				ops.On("WalletWatchOnly", mock.Anything, uint32(7)).Return(
					false, nil,
				).Once()
				ops.On("EnsureScope", mock.Anything, uint32(7), KeyScope{
					Purpose: 49,
					Coin:    0,
				}).Return(int64(8), nil).Once()
				ops.On("AllocateAccountNumber", mock.Anything, int64(8)).Return(
					int64(9), nil,
				).Once()
				ops.On("CreateDerivedAccount", mock.Anything, int64(8),
					int64(9), "savings",
				).Return(
					CreateDerivedAccountRow{}, errTestBoom,
				).Once()

				return ops
			},
			wantErr:         errTestBoom,
			wantWrappedText: "create account: boom",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ops := tc.setupOps()
			t.Cleanup(func() {
				ops.AssertExpectations(t)
			})

			info, err := CreateDerivedAccountWithOps(
				t.Context(), testCreateDerivedAccountParams(), ops,
			)

			require.Nil(t, info)
			require.Error(t, err)
			require.ErrorIs(t, err, tc.wantErr)

			if tc.wantWrappedText != "" {
				require.EqualError(t, err, tc.wantWrappedText)
			}
		})
	}
}

// testCreateDerivedAccountParams returns one valid derived-account request for
// shared helper tests.
func testCreateDerivedAccountParams() CreateDerivedAccountParams {
	return CreateDerivedAccountParams{
		WalletID: 7,
		Scope: KeyScope{
			Purpose: 49,
			Coin:    0,
		},
		Name: "savings",
	}
}

// mockCreateDerivedAccountOps is a mock implementation of
// CreateDerivedAccountOps.
type mockCreateDerivedAccountOps struct {
	mock.Mock
}

var _ CreateDerivedAccountOps = (*mockCreateDerivedAccountOps)(nil)

// WalletWatchOnly implements CreateDerivedAccountOps.
func (m *mockCreateDerivedAccountOps) WalletWatchOnly(ctx context.Context,
	walletID uint32) (bool, error) {

	args := m.Called(ctx, walletID)

	isWatchOnly, ok := args.Get(0).(bool)
	if !ok {
		return false, mockTypeError("WalletWatchOnly result")
	}

	return isWatchOnly, args.Error(1)
}

// EnsureScope implements CreateDerivedAccountOps.
func (m *mockCreateDerivedAccountOps) EnsureScope(ctx context.Context,
	walletID uint32, scope KeyScope) (int64, error) {

	args := m.Called(ctx, walletID, scope)

	scopeID, ok := args.Get(0).(int64)
	if !ok {
		return 0, mockTypeError("EnsureScope result")
	}

	return scopeID, args.Error(1)
}

// AllocateAccountNumber implements CreateDerivedAccountOps.
func (m *mockCreateDerivedAccountOps) AllocateAccountNumber(ctx context.Context,
	scopeID int64) (int64, error) {

	args := m.Called(ctx, scopeID)

	accountNum, ok := args.Get(0).(int64)
	if !ok {
		return 0, mockTypeError("AllocateAccountNumber result")
	}

	return accountNum, args.Error(1)
}

// CreateDerivedAccount implements CreateDerivedAccountOps.
func (m *mockCreateDerivedAccountOps) CreateDerivedAccount(ctx context.Context,
	scopeID int64, accountNumber int64, name string) (CreateDerivedAccountRow,
	error) {

	args := m.Called(ctx, scopeID, accountNumber, name)

	row, ok := args.Get(0).(CreateDerivedAccountRow)
	if !ok {
		return CreateDerivedAccountRow{}, mockTypeError(
			"CreateDerivedAccount result",
		)
	}

	return row, args.Error(1)
}
