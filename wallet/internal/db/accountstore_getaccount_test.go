package db

import (
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const defaultAccountName = "default"

// TestGetAccountWithOps verifies that the shared helper owns the ordered
// account-read workflow and returns the backend-normalized AccountInfo.
func TestGetAccountWithOps(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	accountName := defaultAccountName
	query := GetAccountQuery{
		WalletID: 7,
		Scope:    KeyScope{Purpose: 84, Coin: 0},
		Name:     &accountName,
	}
	rowID := int64(11)
	loaded := &AccountInfo{
		AccountNumber: testUint32Ptr(0),
		AccountName:   defaultAccountName,
		IsImported:    false,
		KeyScope:      query.Scope,
		rowID:         rowID,
	}
	balanced := &AccountInfo{
		AccountNumber:      testUint32Ptr(0),
		AccountName:        defaultAccountName,
		IsImported:         false,
		KeyScope:           query.Scope,
		ConfirmedBalance:   btcutil.Amount(12),
		UnconfirmedBalance: btcutil.Amount(34),
	}

	ops := &mockGetAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	loadCall := ops.On(
		"GetAccountByName", ctx, query,
	).Return(loaded, nil).Once()
	attachCall := ops.On(
		"AttachAccountBalance", ctx, query, rowID, loaded,
	).Return(balanced, nil).Once()

	mock.InOrder(loadCall, attachCall)

	info, err := GetAccountWithOps(ctx, query, ops)

	require.NoError(t, err)
	require.Equal(t, balanced, info)
}

// TestGetAccountWithOpsValidationFailure verifies validation errors
// short-circuit the ops dispatch and prevent backend operations.
func TestGetAccountWithOpsValidationFailure(t *testing.T) {
	t.Parallel()

	ops := &mockGetAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	info, err := GetAccountWithOps(t.Context(), GetAccountQuery{}, ops)

	require.Nil(t, info)
	require.ErrorIs(t, err, ErrInvalidAccountQuery)
	ops.AssertNotCalled(t, "GetAccountByNumber")
	ops.AssertNotCalled(t, "GetAccountByName")
	ops.AssertNotCalled(t, "AttachAccountBalance")
}

// TestGetAccountWithOpsPassesThroughLoadedAccount verifies that after
// successful load, the shared helper forwards the account to balance attachment
// for derived accounts (avoiding the code path where the rejection applies).
func TestGetAccountWithOpsPassesThroughLoadedAccount(t *testing.T) {
	t.Parallel()

	accountNumber := uint32(5)
	ctx := t.Context()
	query := GetAccountQuery{
		WalletID:      7,
		Scope:         KeyScope{Purpose: 84, Coin: 0},
		AccountNumber: &accountNumber,
	}
	rowID := int64(11)
	loaded := &AccountInfo{
		AccountNumber: testUint32Ptr(5),
		AccountName:   "derived",
		IsImported:    false,
		KeyScope:      query.Scope,
		rowID:         rowID,
	}
	balanced := &AccountInfo{
		AccountNumber:      testUint32Ptr(5),
		AccountName:        "derived",
		IsImported:         false,
		KeyScope:           query.Scope,
		ConfirmedBalance:   btcutil.Amount(50),
		UnconfirmedBalance: btcutil.Amount(75),
	}

	ops := &mockGetAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	loadCall := ops.On(
		"GetAccountByNumber", ctx, query,
	).Return(loaded, nil).Once()
	attachCall := ops.On(
		"AttachAccountBalance", ctx, query, rowID, loaded,
	).Return(balanced, nil).Once()
	mock.InOrder(loadCall, attachCall)

	info, err := GetAccountWithOps(ctx, query, ops)

	require.NoError(t, err)
	require.Equal(t, balanced, info)
}

// TestGetAccountWithOpsRejectsImportedByNumber verifies number-based lookups
// reject imported accounts after backend load to keep the shared invariant
// consistent across backends.
func TestGetAccountWithOpsRejectsImportedByNumber(t *testing.T) {
	t.Parallel()

	accountNumber := uint32(5)
	ctx := t.Context()
	query := GetAccountQuery{
		WalletID:      7,
		Scope:         KeyScope{Purpose: 84, Coin: 0},
		AccountNumber: &accountNumber,
	}
	// The importedness flag is authoritative even when the backend uses an
	// internal account number for imported rows.
	loaded := &AccountInfo{
		AccountName: "imported",
		IsImported:  true,
		KeyScope:    query.Scope,
	}

	ops := &mockGetAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On(
		"GetAccountByNumber", ctx, query,
	).Return(loaded, nil).Once()

	info, err := GetAccountWithOps(ctx, query, ops)

	require.Nil(t, info)
	require.EqualError(t, err, "account 5 in scope 84/0: account not found")
	require.ErrorIs(t, err, ErrAccountNotFound)
	ops.AssertNotCalled(t, "AttachAccountBalance")
}

// TestGetAccountWithOpsFormatsNotFound verifies that the shared helper owns
// selector-specific query context when backends report ErrAccountNotFound.
func TestGetAccountWithOpsFormatsNotFound(t *testing.T) {
	t.Parallel()

	accountName := defaultAccountName
	accountNumber := uint32(5)

	tests := []struct {
		name        string
		query       GetAccountQuery
		setup       func(context.Context, *mockGetAccountOps, GetAccountQuery)
		wantErrText string
	}{
		{
			name: "by name",
			query: GetAccountQuery{
				WalletID: 7,
				Scope:    KeyScope{Purpose: 84, Coin: 0},
				Name:     &accountName,
			},
			setup: func(ctx context.Context, ops *mockGetAccountOps,
				query GetAccountQuery) {

				ops.On("GetAccountByName", ctx, query).Return(
					nil, ErrAccountNotFound,
				).Once()
			},
			wantErrText: "account \"default\" in scope 84/0: account not found",
		},
		{
			name: "by number",
			query: GetAccountQuery{
				WalletID:      7,
				Scope:         KeyScope{Purpose: 84, Coin: 0},
				AccountNumber: &accountNumber,
			},
			setup: func(ctx context.Context, ops *mockGetAccountOps,
				query GetAccountQuery) {

				ops.On("GetAccountByNumber", ctx, query).Return(
					nil, ErrAccountNotFound,
				).Once()
			},
			wantErrText: "account 5 in scope 84/0: account not found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			ops := &mockGetAccountOps{}
			t.Cleanup(func() {
				ops.AssertExpectations(t)
			})

			tc.setup(ctx, ops, tc.query)

			info, err := GetAccountWithOps(ctx, tc.query, ops)

			require.Nil(t, info)
			require.EqualError(t, err, tc.wantErrText)
			require.ErrorIs(t, err, ErrAccountNotFound)
			ops.AssertNotCalled(t, "AttachAccountBalance")
		})
	}
}

var errGetAccountBackendTest = errors.New("backend error")

// TestGetAccountWithOpsForwardsStageErrors verifies backend stage errors are
// forwarded and later stages are skipped.
func TestGetAccountWithOpsForwardsStageErrors(t *testing.T) {
	t.Parallel()

	accountName := defaultAccountName
	query := GetAccountQuery{
		WalletID: 7,
		Scope:    KeyScope{Purpose: 84, Coin: 0},
		Name:     &accountName,
	}
	rowID := int64(11)
	loaded := &AccountInfo{
		AccountNumber: testUint32Ptr(0),
		AccountName:   defaultAccountName,
		IsImported:    false,
		KeyScope:      query.Scope,
		rowID:         rowID,
	}

	tests := []struct {
		name     string
		setupOps func(context.Context) *mockGetAccountOps
	}{
		{
			name: "load account",
			setupOps: func(ctx context.Context) *mockGetAccountOps {
				ops := &mockGetAccountOps{}
				ops.On("GetAccountByName", ctx, query).Return(
					nil, errGetAccountBackendTest,
				).Once()

				return ops
			},
		},
		{
			name: "attach balance",
			setupOps: func(ctx context.Context) *mockGetAccountOps {
				ops := &mockGetAccountOps{}
				ops.On("GetAccountByName", ctx, query).Return(
					loaded, nil,
				).Once()
				ops.On(
					"AttachAccountBalance", ctx, query, rowID, loaded,
				).Return(nil, errGetAccountBackendTest).Once()

				return ops
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			ops := tc.setupOps(ctx)
			t.Cleanup(func() {
				ops.AssertExpectations(t)
			})

			info, err := GetAccountWithOps(ctx, query, ops)

			require.Nil(t, info)
			require.ErrorIs(t, err, errGetAccountBackendTest)
		})
	}
}

// mockGetAccountOps is a mock implementation of GetAccountOps.
type mockGetAccountOps struct {
	mock.Mock
}

var _ GetAccountOps = (*mockGetAccountOps)(nil)

// GetAccountByNumber implements GetAccountOps.
func (m *mockGetAccountOps) GetAccountByNumber(ctx context.Context,
	query GetAccountQuery) (*AccountInfo, error) {

	args := m.Called(ctx, query)

	info, ok := args.Get(0).(*AccountInfo)
	if !ok && args.Get(0) != nil {
		return nil, mockTypeError("GetAccountByNumber info result")
	}

	return info, args.Error(1)
}

// GetAccountByName implements GetAccountOps.
func (m *mockGetAccountOps) GetAccountByName(ctx context.Context,
	query GetAccountQuery) (*AccountInfo, error) {

	args := m.Called(ctx, query)

	info, ok := args.Get(0).(*AccountInfo)
	if !ok && args.Get(0) != nil {
		return nil, mockTypeError("GetAccountByName info result")
	}

	return info, args.Error(1)
}

// AttachAccountBalance implements GetAccountOps.
func (m *mockGetAccountOps) AttachAccountBalance(ctx context.Context,
	query GetAccountQuery, accountID int64,
	info *AccountInfo) (*AccountInfo, error) {

	args := m.Called(ctx, query, accountID, info)

	balanced, ok := args.Get(0).(*AccountInfo)
	if !ok && args.Get(0) != nil {
		return nil, mockTypeError("AttachAccountBalance result")
	}

	return balanced, args.Error(1)
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
