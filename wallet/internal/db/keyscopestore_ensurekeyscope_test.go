package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	// Test errors for EnsureKeyScope ops testing.
	errTestGetScope     = errors.New("get scope")
	errTestCreateScope  = errors.New("create scope")
	errTestRefetchScope = errors.New("refetch scope")
)

// Ensure mockEnsureKeyScopeOps implements EnsureKeyScopeOps at compile time.
var _ EnsureKeyScopeOps = (*mockEnsureKeyScopeOps)(nil)

// mockEnsureKeyScopeOps implements EnsureKeyScopeOps for testing.
type mockEnsureKeyScopeOps struct {
	mock.Mock
}

// GetKeyScope returns the scope ID for a given wallet and key scope.
func (m *mockEnsureKeyScopeOps) GetKeyScope(ctx context.Context,
	walletID uint32, scope KeyScope) (int64, error) {

	args := m.Called(ctx, walletID, scope)
	if args.Get(0) == nil {
		return 0, args.Error(1)
	}

	scopeID, ok := args.Get(0).(int64)
	if !ok {
		return 0, mockTypeError("GetKeyScope result")
	}

	return scopeID, args.Error(1)
}

// CreateKeyScope creates a new key scope and returns its ID.
func (m *mockEnsureKeyScopeOps) CreateKeyScope(ctx context.Context,
	walletID uint32, scope KeyScope, addrSchema ScopeAddrSchema) (int64,
	error) {

	args := m.Called(ctx, walletID, scope, addrSchema)
	if args.Get(0) == nil {
		return 0, args.Error(1)
	}

	scopeID, ok := args.Get(0).(int64)
	if !ok {
		return 0, mockTypeError("CreateKeyScope result")
	}

	return scopeID, args.Error(1)
}

// TestEnsureKeyScopeWithOpsExistingFastPath verifies that the shared helper
// returns the existing scope ID and skips creation when the scope already
// exists.
func TestEnsureKeyScopeWithOpsExistingFastPath(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	walletID := uint32(7)
	scope := KeyScope{Purpose: 49, Coin: 0}

	ops := &mockEnsureKeyScopeOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	// Existing scope returns ID directly; no create should happen.
	getCall := ops.On("GetKeyScope", ctx, walletID, scope).Return(
		int64(11), nil,
	).Once()

	mock.InOrder(getCall)

	// Should not call CreateKeyScope.
	ops.AssertNotCalled(t, "CreateKeyScope")

	// Execute.
	scopeID, err := EnsureKeyScopeWithOps(ctx, ops, walletID, scope, nil)

	// Verify.
	require.NoError(t, err)
	require.Equal(t, int64(11), scopeID)
}

// TestEnsureKeyScopeWithOpsMissingDefaultSchemaPath verifies that the shared
// helper creates a missing scope using the default schema when no override is
// provided.
func TestEnsureKeyScopeWithOpsMissingDefaultSchemaPath(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	walletID := uint32(7)
	scope := KeyScope{Purpose: 49, Coin: 0}
	defaultSchema := ScopeAddrMap[scope]

	ops := &mockEnsureKeyScopeOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	// Scope does not exist; get returns ErrNoRows.
	getCall := ops.On("GetKeyScope", ctx, walletID, scope).Return(
		int64(0), sql.ErrNoRows,
	).Once()

	// Create should be called with the default schema (no override).
	createCall := ops.On("CreateKeyScope", ctx, walletID, scope,
		defaultSchema,
	).Return(int64(12), nil).Once()

	mock.InOrder(getCall, createCall)

	// Execute with no schema override.
	scopeID, err := EnsureKeyScopeWithOps(ctx, ops, walletID, scope, nil)

	// Verify.
	require.NoError(t, err)
	require.Equal(t, int64(12), scopeID)
}

// TestEnsureKeyScopeWithOpsMissingSchemaOverridePath verifies that the shared
// helper creates a missing scope using the provided schema override instead of
// the default schema map lookup.
func TestEnsureKeyScopeWithOpsMissingSchemaOverridePath(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	walletID := uint32(7)
	scope := KeyScope{Purpose: 49, Coin: 0}
	overrideSchema := ScopeAddrSchema{
		InternalAddrType: 5,
		ExternalAddrType: 6,
	}

	ops := &mockEnsureKeyScopeOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	// Scope does not exist; get returns ErrNoRows.
	getCall := ops.On("GetKeyScope", ctx, walletID, scope).Return(
		int64(0), sql.ErrNoRows,
	).Once()

	// Create should be called with the provided override schema.
	createCall := ops.On("CreateKeyScope", ctx, walletID, scope,
		overrideSchema,
	).Return(int64(13), nil).Once()

	mock.InOrder(getCall, createCall)

	// Execute with schema override.
	scopeID, err := EnsureKeyScopeWithOps(ctx, ops, walletID, scope,
		&overrideSchema)

	// Verify.
	require.NoError(t, err)
	require.Equal(t, int64(13), scopeID)
}

// TestEnsureKeyScopeWithOpsCreateConflictRefetchPath verifies that when create
// returns sql.ErrNoRows (conflict), the helper refetches the scope created
// concurrently.
func TestEnsureKeyScopeWithOpsCreateConflictRefetchPath(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	walletID := uint32(7)
	scope := KeyScope{Purpose: 49, Coin: 0}
	defaultSchema := ScopeAddrMap[scope]

	ops := &mockEnsureKeyScopeOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	// First get: scope does not exist.
	firstGetCall := ops.On("GetKeyScope", ctx, walletID, scope).Return(
		int64(0), sql.ErrNoRows,
	).Once()

	// Create hits conflict (ON CONFLICT DO NOTHING), returns ErrNoRows.
	createCall := ops.On("CreateKeyScope", ctx, walletID, scope,
		defaultSchema,
	).Return(int64(0), sql.ErrNoRows).Once()

	// Refetch: scope now exists from concurrent creation.
	secondGetCall := ops.On("GetKeyScope", ctx, walletID, scope).Return(
		int64(14), nil,
	).Once()

	mock.InOrder(firstGetCall, createCall, secondGetCall)

	// Execute.
	scopeID, err := EnsureKeyScopeWithOps(ctx, ops, walletID, scope, nil)

	// Verify.
	require.NoError(t, err)
	require.Equal(t, int64(14), scopeID)
}

// TestEnsureKeyScopeWithOpsGetErrorBeforeCreate verifies that errors from the
// initial get are wrapped as "check key scope".
func TestEnsureKeyScopeWithOpsGetErrorBeforeCreate(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	walletID := uint32(7)
	scope := KeyScope{Purpose: 49, Coin: 0}

	ops := &mockEnsureKeyScopeOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	// Get returns a real database error (not ErrNoRows).
	getCall := ops.On("GetKeyScope", ctx, walletID, scope).Return(
		int64(0), errTestGetScope,
	).Once()

	mock.InOrder(getCall)

	// Should not call CreateKeyScope on get error.
	ops.AssertNotCalled(t, "CreateKeyScope")

	// Execute.
	scopeID, err := EnsureKeyScopeWithOps(ctx, ops, walletID, scope, nil)

	// Verify.
	require.Error(t, err)
	require.Equal(t, int64(0), scopeID)
	require.ErrorIs(t, err, errTestGetScope)
	require.Contains(t, err.Error(), "check key scope")
}

// TestEnsureKeyScopeWithOpsCreateErrorWrapping verifies that errors from
// creation (other than ErrNoRows) are wrapped as "create key scope".
func TestEnsureKeyScopeWithOpsCreateErrorWrapping(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	walletID := uint32(7)
	scope := KeyScope{Purpose: 49, Coin: 0}
	defaultSchema := ScopeAddrMap[scope]

	ops := &mockEnsureKeyScopeOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	// Scope does not exist.
	getCall := ops.On("GetKeyScope", ctx, walletID, scope).Return(
		int64(0), sql.ErrNoRows,
	).Once()

	// Create returns a real database error (not ErrNoRows).
	createCall := ops.On("CreateKeyScope", ctx, walletID, scope,
		defaultSchema,
	).Return(int64(0), errTestCreateScope).Once()

	mock.InOrder(getCall, createCall)

	// Execute.
	scopeID, err := EnsureKeyScopeWithOps(ctx, ops, walletID, scope, nil)

	// Verify.
	require.Error(t, err)
	require.Equal(t, int64(0), scopeID)
	require.ErrorIs(t, err, errTestCreateScope)
	require.Contains(t, err.Error(), "create key scope")
}

// TestEnsureKeyScopeWithOpsRefetchErrorAfterCreateConflict verifies that errors
// from the refetching after creation conflict are wrapped as
// "get scope after create".
func TestEnsureKeyScopeWithOpsRefetchErrorAfterCreateConflict(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	walletID := uint32(7)
	scope := KeyScope{Purpose: 49, Coin: 0}
	defaultSchema := ScopeAddrMap[scope]

	ops := &mockEnsureKeyScopeOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	// First get: scope does not exist.
	firstGetCall := ops.On("GetKeyScope", ctx, walletID, scope).Return(
		int64(0), sql.ErrNoRows,
	).Once()

	// Create hits conflict, returns ErrNoRows.
	createCall := ops.On("CreateKeyScope", ctx, walletID, scope,
		defaultSchema,
	).Return(int64(0), sql.ErrNoRows).Once()

	// Refetch fails with a real database error.
	secondGetCall := ops.On("GetKeyScope", ctx, walletID, scope).Return(
		int64(0), errTestRefetchScope,
	).Once()

	mock.InOrder(firstGetCall, createCall, secondGetCall)

	// Execute.
	scopeID, err := EnsureKeyScopeWithOps(ctx, ops, walletID, scope, nil)

	// Verify.
	require.Error(t, err)
	require.Equal(t, int64(0), scopeID)
	require.ErrorIs(t, err, errTestRefetchScope)
	require.Contains(t, err.Error(), "get scope after create")
}

// TestEnsureKeyScopeWithOpsUnknownScopeReturnsError verifies that an unknown
// scope with no schema override returns ErrUnknownKeyScope.
func TestEnsureKeyScopeWithOpsUnknownScopeReturnsError(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	walletID := uint32(7)
	// Use a scope that does not exist in ScopeAddrMap.
	unknownScope := KeyScope{Purpose: 999, Coin: 999}

	ops := &mockEnsureKeyScopeOps{}
	t.Cleanup(func() {
		ops.AssertExpectations(t)
	})

	// Scope does not exist in the database.
	getCall := ops.On("GetKeyScope", ctx, walletID, unknownScope).Return(
		int64(0), sql.ErrNoRows,
	).Once()

	mock.InOrder(getCall)

	// Should not call CreateKeyScope for unknown scope.
	ops.AssertNotCalled(t, "CreateKeyScope")

	// Execute with no override.
	scopeID, err := EnsureKeyScopeWithOps(ctx, ops, walletID, unknownScope, nil)

	// Verify.
	require.Error(t, err)
	require.Equal(t, int64(0), scopeID)
	require.ErrorIs(t, err, ErrUnknownKeyScope)
}
