package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockNewDerivedAddressOps records the exact backend stages reached by the
// shared derived-address workflows.
type mockNewDerivedAddressOps struct {
	mock.Mock
}

var _ NewDerivedAddressOps = (*mockNewDerivedAddressOps)(nil)

// GetAccount records the normalized account lookup used by the workflow.
func (m *mockNewDerivedAddressOps) GetAccount(ctx context.Context,
	key AccountLookupKey) (DerivedAddressAccount, error) {

	args := m.Called(ctx, key)
	account, _ := args.Get(0).(DerivedAddressAccount)

	return account, args.Error(1)
}

// NextIndex records the branch counter allocation used by the workflow.
func (m *mockNewDerivedAddressOps) NextIndex(ctx context.Context,
	accountID int64, change bool) (int64, error) {

	args := m.Called(ctx, accountID, change)
	index, _ := args.Get(0).(int64)

	return index, args.Error(1)
}

// AddressOwned records transaction-local ownership checks used by batches.
func (m *mockNewDerivedAddressOps) AddressOwned(ctx context.Context,
	walletID int64, scriptPubKey []byte) (bool, error) {

	args := m.Called(ctx, walletID, scriptPubKey)

	return args.Bool(0), args.Error(1)
}

// CreateDerivedAddress records the row and derivation-path insertion request.
func (m *mockNewDerivedAddressOps) CreateDerivedAddress(ctx context.Context,
	req CreateDerivedAddressRequest) (CreateDerivedAddressRow, error) {

	args := m.Called(ctx, req)
	row, _ := args.Get(0).(CreateDerivedAddressRow)

	return row, args.Error(1)
}

// TestNewDerivedAddressWithOpsNilDeriveFn verifies that the shared workflow
// rejects a missing derivation callback before touching the backend adapter.
func TestNewDerivedAddressWithOpsNilDeriveFn(t *testing.T) {
	t.Parallel()

	// Arrange: Keep the strict ops mock free of expectations so any backend
	// call proves validation happened too late.
	ops := &mockNewDerivedAddressOps{}

	// Act: Invoke the shared workflow without the required derivation
	// callback.
	_, err := NewDerivedAddressWithOps(
		t.Context(), NewDerivedAddressParams{}, ops, nil,
	)

	// Assert: The callback error is returned before the backend is touched.
	require.ErrorIs(t, err, errNilAddressDerivationFunc)
}

// TestNewDerivedAddressWithOpsBuildsInfo verifies that the workflow threads the
// account lookup key, index allocation, and insert request through the adapter
// and assembles the resulting AddressInfo with its account metadata.
func TestNewDerivedAddressWithOpsBuildsInfo(t *testing.T) {
	t.Parallel()

	now := time.Unix(1710005000, 0).UTC()
	params := NewDerivedAddressParams{
		WalletID:    7,
		AccountName: "acct",
		Scope:       KeyScopeBIP0084,
	}

	account := DerivedAddressAccount{
		AccountID:     42,
		AccountNumber: sqlNullInt64(3),
		AccountName:   params.AccountName,
		Purpose:       int64(params.Scope.Purpose),
		CoinType:      int64(params.Scope.Coin),
		IsDerived:     true,
		AddrSchema: ScopeAddrSchema{
			ExternalAddrType: WitnessPubKey,
			InternalAddrType: WitnessPubKey,
		},
	}

	// Arrange: Require each shared-workflow stage once with the complete
	// normalized account key and derived-address insert request.
	ops := &mockNewDerivedAddressOps{}
	ops.On(
		"GetAccount", mock.Anything, AccountKeyFromParams(params),
	).Return(account, nil).Once()
	ops.On(
		"NextIndex", mock.Anything, int64(42), false,
	).Return(int64(5), nil).Once()
	ops.On(
		"CreateDerivedAddress", mock.Anything,
		CreateDerivedAddressRequest{
			WalletID:     int64(params.WalletID),
			AccountID:    42,
			AddrType:     WitnessPubKey,
			Index:        5,
			ScriptPubKey: []byte{1},
			PubKey:       []byte{2},
		},
	).Return(CreateDerivedAddressRow{
		ID:        99,
		CreatedAt: now,
	}, nil).Once()

	deriveFn := func(_ context.Context, p AddressDerivationParams) (
		*DerivedAddressData, error) {

		require.Equal(t, uint32(3), *p.DerivedAccountNumber)
		require.Equal(t, uint32(5), p.Index)

		return &DerivedAddressData{
			ScriptPubKey: []byte{1},
			PubKey:       []byte{2},
		}, nil
	}

	// Act: Run count-one allocation through the shared workflow.
	info, err := NewDerivedAddressWithOps(t.Context(), params, ops, deriveFn)

	// Assert: The returned metadata matches the account and inserted row, and
	// every required backend stage ran exactly once.
	require.NoError(t, err)
	require.Equal(t, uint32(99), info.ID)
	require.Equal(t, params.AccountName, info.AccountName)
	require.Equal(t, params.Scope, info.KeyScope)
	require.Equal(t, uint32(3), *info.AccountNumber)
	ops.AssertExpectations(t)
}

// TestNewDerivedAddressWithOpsRejectsDerivedAccountWithoutNumber verifies a
// wallet-derived account missing its derived account number is rejected
// instead of being treated as an imported-xpub account, before deriving.
func TestNewDerivedAddressWithOpsRejectsDerivedAccountWithoutNumber(
	t *testing.T) {

	t.Parallel()

	params := NewDerivedAddressParams{
		WalletID:    7,
		AccountName: "acct",
		Scope:       KeyScopeBIP0084,
	}
	deriveCalled := false

	// Arrange: Return a derived account whose missing account number violates
	// the stored account-shape invariant, and observe any derivation attempt.
	ops := &mockNewDerivedAddressOps{}
	ops.On(
		"GetAccount", mock.Anything, AccountKeyFromParams(params),
	).Return(DerivedAddressAccount{
		AccountID:   42,
		AccountName: params.AccountName,
		IsDerived:   true,
	}, nil).Once()

	deriveFn := func(context.Context,
		AddressDerivationParams) (*DerivedAddressData, error) {

		deriveCalled = true

		return &DerivedAddressData{}, nil
	}

	// Act: Run allocation with the corrupt account shape.
	_, err := NewDerivedAddressWithOps(t.Context(), params, ops, deriveFn)

	// Assert: Preflight rejects the account before derivation and satisfies
	// only the required account lookup.
	require.ErrorIs(t, err, errAccountShapeCorruption)
	require.False(t, deriveCalled)
	ops.AssertExpectations(t)
}

// TestDerivedAddressInputNilDerivedData verifies that the shared derivation
// path rejects a nil callback result before dereferencing it.
func TestDerivedAddressInputNilDerivedData(t *testing.T) {
	t.Parallel()

	// Arrange: Return nil derived data after allocating one exact child index.
	params := NewDerivedAddressParams{
		Scope: KeyScopeBIP0084,
	}

	deriveFn := func(context.Context,
		AddressDerivationParams) (*DerivedAddressData, error) {

		var derivedData *DerivedAddressData

		return derivedData, nil
	}

	accountNumber := uint32(0)
	account := DerivedAddressAccount{
		AccountID: 1,
		AddrSchema: ScopeAddrSchema{
			ExternalAddrType: PubKeyHash,
			InternalAddrType: PubKeyHash,
		},
	}
	ops := &mockNewDerivedAddressOps{}
	ops.On(
		"NextIndex", mock.Anything, int64(1), false,
	).Return(int64(7), nil).Once()

	// Act: Invoke the leaf-input stage directly to isolate nil callback data.
	addrType, branch, index, scriptPubKey, pubKey, err := derivedAddressInput(
		t.Context(), params, account, &accountNumber, ops, deriveFn,
	)

	// Assert: No partial address material escapes and the allocation stage ran
	// once before the callback returned its invalid result.
	require.Zero(t, addrType)
	require.Zero(t, branch)
	require.Zero(t, index)
	require.Nil(t, scriptPubKey)
	require.Nil(t, pubKey)
	require.ErrorIs(t, err, errNilDerivedAddressData)
	ops.AssertExpectations(t)
}
