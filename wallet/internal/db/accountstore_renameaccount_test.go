package db

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestRenameAccountWithOpsValidationFailure verifies that validation errors
// short-circuit the ops dispatch and prevent backend operations.
func TestRenameAccountWithOpsValidationFailure(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	// Missing NewName fails validation.
	ops := &mockRenameAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	err := RenameAccountWithOps(
		ctx,
		RenameAccountParams{OldName: "old"},
		ops,
	)
	require.ErrorIs(t, err, ErrMissingAccountName)
	ops.AssertNotCalled(t, "RenameByNumber")
	ops.AssertNotCalled(t, "RenameByName")

	// Both OldName and AccountNumber set fails validation.
	ops = &mockRenameAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	err = RenameAccountWithOps(
		ctx,
		RenameAccountParams{
			NewName:       "new",
			OldName:       "old",
			AccountNumber: ptrUint32(5),
		},
		ops,
	)
	require.ErrorIs(t, err, ErrInvalidAccountQuery)
	ops.AssertNotCalled(t, "RenameByNumber")
	ops.AssertNotCalled(t, "RenameByName")

	// Neither OldName nor AccountNumber set fails validation.
	ops = &mockRenameAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	err = RenameAccountWithOps(
		ctx,
		RenameAccountParams{NewName: "new"},
		ops,
	)
	require.ErrorIs(t, err, ErrInvalidAccountQuery)
	ops.AssertNotCalled(t, "RenameByNumber")
	ops.AssertNotCalled(t, "RenameByName")
}

// TestRenameAccountWithOpsDispatchesByNumber verifies the helper invokes
// RenameByNumber when AccountNumber is set.
func TestRenameAccountWithOpsDispatchesByNumber(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	params := RenameAccountParams{
		NewName:       "new",
		AccountNumber: ptrUint32(5),
		Scope:         KeyScope{Purpose: 44, Coin: 0},
		WalletID:      1,
	}

	ops := &mockRenameAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("RenameByNumber", ctx, params).Return(int64(1), nil).Once()

	err := RenameAccountWithOps(ctx, params, ops)

	require.NoError(t, err)
	ops.AssertCalled(t, "RenameByNumber", ctx, params)
	ops.AssertNotCalled(t, "RenameByName")
}

// TestRenameAccountWithOpsDispatchesByName verifies the helper invokes
// RenameByName when OldName is set.
func TestRenameAccountWithOpsDispatchesByName(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	params := RenameAccountParams{
		NewName:  "new",
		OldName:  "old",
		Scope:    KeyScope{Purpose: 44, Coin: 0},
		WalletID: 1,
	}

	ops := &mockRenameAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("RenameByName", ctx, params).Return(int64(1), nil).Once()

	err := RenameAccountWithOps(ctx, params, ops)

	require.NoError(t, err)
	ops.AssertNotCalled(t, "RenameByNumber")
	ops.AssertCalled(t, "RenameByName", ctx, params)
}

// TestRenameAccountWithOpsReturnsNotFoundByNumber verifies the helper returns
// a not-found error when RenameByNumber affects zero rows.
func TestRenameAccountWithOpsReturnsNotFoundByNumber(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	params := RenameAccountParams{
		NewName:       "new",
		AccountNumber: ptrUint32(5),
		Scope:         KeyScope{Purpose: 44, Coin: 0},
		WalletID:      1,
	}

	ops := &mockRenameAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("RenameByNumber", ctx, params).Return(int64(0), nil).Once()

	err := RenameAccountWithOps(ctx, params, ops)

	require.Error(t, err)
	require.ErrorIs(t, err, ErrAccountNotFound)
	require.Contains(t, err.Error(), "account 5")
}

// TestRenameAccountWithOpsReturnsNotFoundByName verifies the helper returns
// a not-found error when RenameByName affects zero rows.
func TestRenameAccountWithOpsReturnsNotFoundByName(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	params := RenameAccountParams{
		NewName:  "new",
		OldName:  "old",
		Scope:    KeyScope{Purpose: 44, Coin: 0},
		WalletID: 1,
	}

	ops := &mockRenameAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("RenameByName", ctx, params).Return(int64(0), nil).Once()

	err := RenameAccountWithOps(ctx, params, ops)

	require.Error(t, err)
	require.ErrorIs(t, err, ErrAccountNotFound)
	require.Contains(t, err.Error(), "account \"old\"")
}

var errRenameBackendTest = errors.New("backend error")

// TestRenameAccountWithOpsForwardsBackendError verifies that errors returned
// by the backend ops are wrapped and forwarded.
func TestRenameAccountWithOpsForwardsBackendError(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	params := RenameAccountParams{
		NewName:       "new",
		AccountNumber: ptrUint32(5),
		Scope:         KeyScope{Purpose: 44, Coin: 0},
		WalletID:      1,
	}

	ops := &mockRenameAccountOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	ops.On("RenameByNumber", ctx, params).
		Return(int64(0), errRenameBackendTest).Once()

	err := RenameAccountWithOps(ctx, params, ops)

	require.Error(t, err)
	require.ErrorIs(t, err, errRenameBackendTest)
	require.Contains(t, err.Error(), "rename account:")
}

// mockRenameAccountOps is a mock implementation of RenameAccountOps.
type mockRenameAccountOps struct {
	mock.Mock
}

var _ RenameAccountOps = (*mockRenameAccountOps)(nil)

// RenameByNumber implements RenameAccountOps.
func (m *mockRenameAccountOps) RenameByNumber(ctx context.Context,
	params RenameAccountParams) (int64, error) {

	args := m.Called(ctx, params)

	rowsAffected, ok := args.Get(0).(int64)
	if !ok {
		return 0, mockTypeError("RenameByNumber result")
	}

	return rowsAffected, args.Error(1)
}

// RenameByName implements RenameAccountOps.
func (m *mockRenameAccountOps) RenameByName(ctx context.Context,
	params RenameAccountParams) (int64, error) {

	args := m.Called(ctx, params)

	rowsAffected, ok := args.Get(0).(int64)
	if !ok {
		return 0, mockTypeError("RenameByName result")
	}

	return rowsAffected, args.Error(1)
}

// ptrUint32 is a test helper that returns a pointer to a uint32.
func ptrUint32(v uint32) *uint32 {
	return &v
}

// TestRenameAccountParamsValidate verifies account renames must include a new
// name and exactly one account selector. Table-driven cases cover both valid
// selectors and the invalid combinations.
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
