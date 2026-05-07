package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	// Test errors for CreateDerivedAccount ops testing.
	errTestWallet = errors.New("wallet")
	errTestScope  = errors.New("scope")
	errTestBoom   = errors.New("boom")
)

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
	ops := newValidCreateDerivedAccountOps()
	ops.walletWatchOnly = true
	ops.ensureScopeID = 11
	ops.accountNumber = 12
	ops.row = CreateDerivedAccountRow{
		AccountNumber: sql.NullInt64{Int64: 12, Valid: true},
		CreatedAt:     createdAt,
	}

	ctx := t.Context()
	info, err := CreateDerivedAccountWithOps(ctx, params, ops)

	require.NoError(t, err)
	require.Equal(t, []string{
		"WalletWatchOnly",
		"EnsureScope",
		"AllocateAccountNumber",
		"CreateDerivedAccount",
	}, ops.calls)
	require.Equal(t, params.WalletID, ops.walletID)
	require.Equal(t, params.WalletID, ops.ensureWalletID)
	require.Equal(t, params.Scope, ops.ensureScope)
	require.Equal(t, int64(11), ops.allocateScopeID)
	require.Equal(t, int64(11), ops.createScopeID)
	require.Equal(t, int64(12), ops.createAccountNumber)
	require.Equal(t, params.Name, ops.createName)
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

	ops := newValidCreateDerivedAccountOps()

	info, err := CreateDerivedAccountWithOps(t.Context(),
		CreateDerivedAccountParams{}, ops,
	)

	require.Nil(t, info)
	require.ErrorIs(t, err, ErrMissingAccountName)
	require.Empty(t, ops.calls)
}

// TestCreateDerivedAccountWithOpsMissingAccountNumber verifies that the shared
// helper rejects a backend row with a nil account number.
func TestCreateDerivedAccountWithOpsMissingAccountNumber(t *testing.T) {
	t.Parallel()

	ops := newValidCreateDerivedAccountOps()
	ops.ensureScopeID = 8
	ops.accountNumber = 9
	ops.row = CreateDerivedAccountRow{
		CreatedAt: time.Unix(456, 0),
	}

	info, err := CreateDerivedAccountWithOps(t.Context(),
		testCreateDerivedAccountParams(), ops,
	)

	require.Nil(t, info)
	require.ErrorIs(t, err, ErrNilDBAccountNumber)
}

// TestCreateDerivedAccountWithOpsMaxAccountNumber verifies that the shared
// helper preserves the existing max-account-number error mapping.
func TestCreateDerivedAccountWithOpsMaxAccountNumber(t *testing.T) {
	t.Parallel()

	ops := newValidCreateDerivedAccountOps()
	ops.ensureScopeID = 8
	ops.accountNumber = int64(^uint32(0)) + 1
	ops.row = CreateDerivedAccountRow{
		AccountNumber: sql.NullInt64{
			Int64: int64(^uint32(0)) + 1,
			Valid: true,
		},
		CreatedAt: time.Unix(789, 0),
	}

	info, err := CreateDerivedAccountWithOps(t.Context(),
		testCreateDerivedAccountParams(), ops,
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
		setupOps        func() *stubCreateDerivedAccountOps
		wantErr         error
		wantWrappedText string
		wantCalls       []string
	}{
		{
			name: "wallet watch only",
			setupOps: func() *stubCreateDerivedAccountOps {
				ops := newValidCreateDerivedAccountOps()
				ops.walletErr = errTestWallet
				return ops
			},
			wantErr:   errTestWallet,
			wantCalls: []string{"WalletWatchOnly"},
		},
		{
			name: "ensure scope",
			setupOps: func() *stubCreateDerivedAccountOps {
				ops := newValidCreateDerivedAccountOps()
				ops.ensureScopeErr = errTestScope
				return ops
			},
			wantErr:   errTestScope,
			wantCalls: []string{"WalletWatchOnly", "EnsureScope"},
		},
		{
			name: "allocate account number",
			setupOps: func() *stubCreateDerivedAccountOps {
				ops := newValidCreateDerivedAccountOps()
				ops.ensureScopeID = 8
				ops.allocateErr = errTestBoom

				return ops
			},
			wantErr:         errTestBoom,
			wantWrappedText: "allocate account number: boom",
			wantCalls: []string{
				"WalletWatchOnly",
				"EnsureScope",
				"AllocateAccountNumber",
			},
		},
		{
			name: "create account",
			setupOps: func() *stubCreateDerivedAccountOps {
				ops := newValidCreateDerivedAccountOps()
				ops.ensureScopeID = 8
				ops.accountNumber = 9
				ops.createErr = errTestBoom

				return ops
			},
			wantErr:         errTestBoom,
			wantWrappedText: "create account: boom",
			wantCalls: []string{
				"WalletWatchOnly",
				"EnsureScope",
				"AllocateAccountNumber",
				"CreateDerivedAccount",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ops := tc.setupOps()

			info, err := CreateDerivedAccountWithOps(t.Context(),
				testCreateDerivedAccountParams(), ops,
			)

			require.Nil(t, info)
			require.Error(t, err)
			require.ErrorIs(t, err, tc.wantErr)

			if tc.wantWrappedText != "" {
				require.EqualError(t, err, tc.wantWrappedText)
			}

			require.Equal(t, tc.wantCalls, ops.calls)
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

// newValidCreateDerivedAccountOps returns a stub adapter with valid defaults
// for all backend stages so each test only overrides the fields relevant to
// that case.
func newValidCreateDerivedAccountOps() *stubCreateDerivedAccountOps {
	return &stubCreateDerivedAccountOps{
		walletWatchOnly: false,
		ensureScopeID:   1,
		accountNumber:   1,
		row: CreateDerivedAccountRow{
			AccountNumber: sql.NullInt64{Int64: 1, Valid: true},
			CreatedAt:     time.Unix(1, 0),
		},
	}
}

// stubCreateDerivedAccountOps is a deterministic test adapter for the shared
// CreateDerivedAccount helper.
type stubCreateDerivedAccountOps struct {
	walletWatchOnly bool
	walletErr       error
	ensureScopeID   int64
	ensureScopeErr  error
	accountNumber   int64
	allocateErr     error
	row             CreateDerivedAccountRow
	createErr       error

	calls               []string
	walletID            uint32
	ensureWalletID      uint32
	ensureScope         KeyScope
	allocateScopeID     int64
	createScopeID       int64
	createAccountNumber int64
	createName          string
}

var _ CreateDerivedAccountOps = (*stubCreateDerivedAccountOps)(nil)

// WalletWatchOnly implements CreateDerivedAccountOps.
func (s *stubCreateDerivedAccountOps) WalletWatchOnly(ctx context.Context,
	walletID uint32) (bool, error) {

	s.calls = append(s.calls, "WalletWatchOnly")
	s.walletID = walletID

	return s.walletWatchOnly, s.walletErr
}

// EnsureScope implements CreateDerivedAccountOps.
func (s *stubCreateDerivedAccountOps) EnsureScope(ctx context.Context,
	walletID uint32, scope KeyScope) (int64, error) {

	s.calls = append(s.calls, "EnsureScope")
	s.ensureWalletID = walletID
	s.ensureScope = scope

	return s.ensureScopeID, s.ensureScopeErr
}

// AllocateAccountNumber implements CreateDerivedAccountOps.
func (s *stubCreateDerivedAccountOps) AllocateAccountNumber(ctx context.Context,
	scopeID int64) (int64, error) {

	s.calls = append(s.calls, "AllocateAccountNumber")
	s.allocateScopeID = scopeID

	return s.accountNumber, s.allocateErr
}

// CreateDerivedAccount implements CreateDerivedAccountOps.
func (s *stubCreateDerivedAccountOps) CreateDerivedAccount(ctx context.Context,
	scopeID int64, accountNumber int64,
	name string) (CreateDerivedAccountRow, error) {

	s.calls = append(s.calls, "CreateDerivedAccount")
	s.createScopeID = scopeID
	s.createAccountNumber = accountNumber
	s.createName = name

	if s.createErr != nil {
		return CreateDerivedAccountRow{}, s.createErr
	}

	return s.row, nil
}
