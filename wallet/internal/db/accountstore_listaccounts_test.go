package db

import (
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestListAccountsWithOpsDispatchesByScope verifies that the shared helper
// chooses the scope-filtered list stage and then attaches balances.
func TestListAccountsWithOpsDispatchesByScope(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	scope := KeyScope{Purpose: 84, Coin: 0}
	query := ListAccountsQuery{WalletID: 7, Scope: &scope}
	infos := []AccountInfo{{
		AccountName:   "default",
		AccountNumber: 0,
		KeyScope:      scope,
	}}
	accounts := []AccountInfo{{
		AccountName:        "default",
		AccountNumber:      0,
		KeyScope:           scope,
		ConfirmedBalance:   btcutil.Amount(12),
		UnconfirmedBalance: btcutil.Amount(34),
	}}

	ops := &mockListAccountsOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	listCall := ops.On(
		"ListByScope", ctx, query,
	).Return(infos, nil).Once()
	attachCall := ops.On(
		"AttachAccountBalances", ctx, query.WalletID, infos,
	).Return(accounts, nil).Once()
	mock.InOrder(listCall, attachCall)

	got, err := ListAccountsWithOps(ctx, query, ops)

	require.NoError(t, err)
	require.Equal(t, accounts, got)
	ops.AssertNotCalled(t, "ListByName")
	ops.AssertNotCalled(t, "ListAll")
}

// TestListAccountsWithOpsDispatchesByName verifies that the shared helper
// chooses the name-filtered list stage and then attaches balances.
func TestListAccountsWithOpsDispatchesByName(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	name := defaultAccountName
	query := ListAccountsQuery{WalletID: 7, Name: &name}
	infos := []AccountInfo{{AccountName: name}}
	accounts := []AccountInfo{{AccountName: name}}

	ops := &mockListAccountsOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	listCall := ops.On(
		"ListByName", ctx, query,
	).Return(infos, nil).Once()
	attachCall := ops.On(
		"AttachAccountBalances", ctx, query.WalletID, infos,
	).Return(accounts, nil).Once()
	mock.InOrder(listCall, attachCall)

	got, err := ListAccountsWithOps(ctx, query, ops)

	require.NoError(t, err)
	require.Equal(t, accounts, got)
	ops.AssertNotCalled(t, "ListByScope")
	ops.AssertNotCalled(t, "ListAll")
}

// TestListAccountsWithOpsDispatchesAll verifies that the shared helper chooses
// the unfiltered list stage when no optional filters are set.
func TestListAccountsWithOpsDispatchesAll(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	query := ListAccountsQuery{WalletID: 7}
	infos := []AccountInfo{{AccountName: "default"}}
	accounts := []AccountInfo{{AccountName: "default"}}

	ops := &mockListAccountsOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	listCall := ops.On(
		"ListAll", ctx, query,
	).Return(infos, nil).Once()
	attachCall := ops.On(
		"AttachAccountBalances", ctx, query.WalletID, infos,
	).Return(accounts, nil).Once()
	mock.InOrder(listCall, attachCall)

	got, err := ListAccountsWithOps(ctx, query, ops)

	require.NoError(t, err)
	require.Equal(t, accounts, got)
	ops.AssertNotCalled(t, "ListByScope")
	ops.AssertNotCalled(t, "ListByName")
}

// TestListAccountsWithOpsValidationFailure verifies validation errors
// short-circuit the ops dispatch and prevent backend operations.
func TestListAccountsWithOpsValidationFailure(t *testing.T) {
	t.Parallel()

	scope := KeyScope{Purpose: 84, Coin: 0}
	name := defaultAccountName
	query := ListAccountsQuery{WalletID: 7, Scope: &scope, Name: &name}

	ops := &mockListAccountsOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	accounts, err := ListAccountsWithOps(t.Context(), query, ops)

	require.Nil(t, accounts)
	require.ErrorIs(t, err, ErrInvalidAccountQuery)
	ops.AssertNotCalled(t, "ListByScope")
	ops.AssertNotCalled(t, "ListByName")
	ops.AssertNotCalled(t, "ListAll")
	ops.AssertNotCalled(t, "AttachAccountBalances")
}

var errListAccountsBackendTest = errors.New("backend error")

// TestListAccountsWithOpsSkipsBalanceAttachment verifies SkipBalance short-
// circuits before the attach stage and returns the loaded infos directly.
func TestListAccountsWithOpsSkipsBalanceAttachment(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	query := ListAccountsQuery{WalletID: 7, SkipBalance: true}
	infos := []AccountInfo{{AccountName: "default"}}

	ops := &mockListAccountsOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("ListAll", ctx, query).Return(infos, nil).Once()

	accounts, err := ListAccountsWithOps(ctx, query, ops)

	require.NoError(t, err)
	require.Equal(t, infos, accounts)
	ops.AssertNotCalled(t, "AttachAccountBalances")
}

// TestListAccountsWithOpsForwardsStageErrors verifies backend stage errors are
// forwarded and later stages are skipped.
func TestListAccountsWithOpsForwardsStageErrors(t *testing.T) {
	t.Parallel()

	query := ListAccountsQuery{WalletID: 7}
	infos := []AccountInfo{{AccountName: "default"}}

	tests := []struct {
		name     string
		setupOps func(context.Context) *mockListAccountsOps
	}{
		{
			name: "list all",
			setupOps: func(ctx context.Context) *mockListAccountsOps {
				ops := &mockListAccountsOps{}
				ops.On("ListAll", ctx, query).Return(
					nil, errListAccountsBackendTest,
				).Once()

				return ops
			},
		},
		{
			name: "attach balances",
			setupOps: func(ctx context.Context) *mockListAccountsOps {
				ops := &mockListAccountsOps{}
				ops.On("ListAll", ctx, query).Return(infos, nil).Once()
				ops.On(
					"AttachAccountBalances", ctx, query.WalletID, infos,
				).Return(
					nil, errListAccountsBackendTest,
				).Once()

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

			accounts, err := ListAccountsWithOps(ctx, query, ops)

			require.Nil(t, accounts)
			require.ErrorIs(t, err, errListAccountsBackendTest)
		})
	}
}

// mockListAccountsOps is a mock implementation of ListAccountsOps.
type mockListAccountsOps struct {
	mock.Mock
}

var _ ListAccountsOps = (*mockListAccountsOps)(nil)

// ListByScope implements ListAccountsOps.
func (m *mockListAccountsOps) ListByScope(ctx context.Context,
	query ListAccountsQuery) ([]AccountInfo, error) {

	args := m.Called(ctx, query)

	infos, ok := args.Get(0).([]AccountInfo)
	if !ok && args.Get(0) != nil {
		return nil, mockTypeError("ListByScope result")
	}

	return infos, args.Error(1)
}

// ListByName implements ListAccountsOps.
func (m *mockListAccountsOps) ListByName(ctx context.Context,
	query ListAccountsQuery) ([]AccountInfo, error) {

	args := m.Called(ctx, query)

	infos, ok := args.Get(0).([]AccountInfo)
	if !ok && args.Get(0) != nil {
		return nil, mockTypeError("ListByName result")
	}

	return infos, args.Error(1)
}

// ListAll implements ListAccountsOps.
func (m *mockListAccountsOps) ListAll(ctx context.Context,
	query ListAccountsQuery) ([]AccountInfo, error) {

	args := m.Called(ctx, query)

	infos, ok := args.Get(0).([]AccountInfo)
	if !ok && args.Get(0) != nil {
		return nil, mockTypeError("ListAll result")
	}

	return infos, args.Error(1)
}

// AttachAccountBalances implements ListAccountsOps.
func (m *mockListAccountsOps) AttachAccountBalances(
	ctx context.Context,
	walletID uint32,
	infos []AccountInfo) ([]AccountInfo, error) {

	args := m.Called(ctx, walletID, infos)

	accounts, ok := args.Get(0).([]AccountInfo)
	if !ok && args.Get(0) != nil {
		return nil, mockTypeError("AttachAccountBalances result")
	}

	return accounts, args.Error(1)
}

// TestListAccountsQueryValidate verifies account lists allow at most one
// optional filter.
func TestListAccountsQueryValidate(t *testing.T) {
	t.Parallel()

	scope := KeyScope{Purpose: 84, Coin: 0}
	name := "default"

	tests := []struct {
		name    string
		query   ListAccountsQuery
		wantErr error
	}{
		{
			name:  "no filter",
			query: ListAccountsQuery{},
		},
		{
			name:  "scope filter",
			query: ListAccountsQuery{Scope: &scope},
		},
		{
			name:  "name filter",
			query: ListAccountsQuery{Name: &name},
		},
		{
			name: "both filters",
			query: ListAccountsQuery{
				Scope: &scope,
				Name:  &name,
			},
			wantErr: ErrInvalidAccountQuery,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.query.Validate()
			require.ErrorIs(t, err, test.wantErr)
		})
	}
}
