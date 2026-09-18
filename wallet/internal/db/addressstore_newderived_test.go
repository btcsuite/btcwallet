package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockNewDerivedAddressOps checks the backend calls used by address allocation.
// Explicit expectations reject writes on paths that must stop at validation.
type mockNewDerivedAddressOps struct {
	mock.Mock
}

var _ NewDerivedAddressOps = (*mockNewDerivedAddressOps)(nil)

// GetAccount implements NewDerivedAddressOps using the expected account lookup.
func (m *mockNewDerivedAddressOps) GetAccount(ctx context.Context,
	key AccountLookupKey) (DerivedAddressAccount, error) {

	args := m.Called(ctx, key)

	account, ok := args.Get(0).(DerivedAddressAccount)
	if !ok {
		return DerivedAddressAccount{}, mockTypeError("GetAccount result")
	}

	return account, args.Error(1)
}

// NextIndex implements NewDerivedAddressOps using the expected branch counter.
func (m *mockNewDerivedAddressOps) NextIndex(ctx context.Context,
	accountID int64, change bool) (int64, error) {

	args := m.Called(ctx, accountID, change)

	index, ok := args.Get(0).(int64)
	if !ok {
		return 0, mockTypeError("NextIndex result")
	}

	return index, args.Error(1)
}

// CreateDerivedAddress implements NewDerivedAddressOps using the expected row.
func (m *mockNewDerivedAddressOps) CreateDerivedAddress(ctx context.Context,
	req CreateDerivedAddressRequest) (CreateDerivedAddressRow, error) {

	args := m.Called(ctx, req)

	row, ok := args.Get(0).(CreateDerivedAddressRow)
	if !ok {
		return CreateDerivedAddressRow{}, mockTypeError(
			"CreateDerivedAddress result",
		)
	}

	return row, args.Error(1)
}

// TestNewDerivedAddressesWithOpsNilDeriveFn verifies that a missing callback
// is rejected before touching the backend adapter.
func TestNewDerivedAddressesWithOpsNilDeriveFn(t *testing.T) {
	t.Parallel()

	// Arrange: Allow no backend calls because the callback is required before
	// any account lookup or counter mutation can occur.
	ops := &mockNewDerivedAddressOps{}

	// Act: Request one child through the same workflow used by SQL stores.
	addresses, exhausted, err := NewDerivedAddressesWithOps(
		t.Context(), NewDerivedAddressParams{}, 1, ops, nil,
	)

	// Assert: Admission fails without rows or exhaustion, and no backend
	// operation was needed to detect the missing callback.
	require.ErrorIs(t, err, errNilAddressDerivationFunc)
	require.Nil(t, addresses)
	require.False(t, exhausted)
	ops.AssertExpectations(t)
}

// TestNewDerivedAddressesWithOpsBuildsInfo verifies that count-one allocation
// forwards account and child identity and assembles the returned metadata.
func TestNewDerivedAddressesWithOpsBuildsInfo(t *testing.T) {
	t.Parallel()

	// Arrange: Expect one lookup, counter advance and insert for a non-default
	// account, so the returned locator must use the resolved account number.
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
	ops := &mockNewDerivedAddressOps{}
	ops.On("GetAccount", t.Context(), AccountLookupKey{
		WalletID:    int64(params.WalletID),
		Purpose:     int64(params.Scope.Purpose),
		CoinType:    int64(params.Scope.Coin),
		AccountName: params.AccountName,
	}).Return(account, nil).Once()
	ops.On("NextIndex", t.Context(), int64(42), false).Return(
		int64(5), nil,
	).Once()
	ops.On("CreateDerivedAddress", t.Context(), CreateDerivedAddressRequest{
		WalletID:     int64(params.WalletID),
		AccountID:    42,
		AddrType:     WitnessPubKey,
		Branch:       0,
		Index:        5,
		ScriptPubKey: []byte{1},
		PubKey:       []byte{2},
	}).Return(CreateDerivedAddressRow{
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

	// Act: Allocate one child through the production batch workflow.
	addresses, exhausted, err := NewDerivedAddressesWithOps(
		t.Context(), params, 1, ops, deriveFn,
	)

	// Assert: The sole result retains the persisted identity and account
	// metadata, with exactly the expected backend operations completed.
	require.NoError(t, err)
	require.False(t, exhausted)
	require.Len(t, addresses, 1)
	info := addresses[0]
	require.Equal(t, uint32(99), info.ID)
	require.Equal(t, params.AccountName, info.AccountName)
	require.Equal(t, params.Scope, info.KeyScope)
	require.Equal(t, uint32(3), *info.AccountNumber)
	ops.AssertExpectations(t)
}

// TestNewDerivedAddressesWithOpsRejectsDerivedAccountWithoutNumber verifies
// that malformed wallet-derived accounts fail before child derivation.
func TestNewDerivedAddressesWithOpsRejectsDerivedAccountWithoutNumber(
	t *testing.T) {

	t.Parallel()

	// Arrange: Return a derived account with a NULL account number. No counter
	// or insert expectation is allowed, because this account cannot be used.
	params := NewDerivedAddressParams{
		WalletID:    7,
		AccountName: "acct",
		Scope:       KeyScopeBIP0084,
	}
	ops := &mockNewDerivedAddressOps{}
	ops.On("GetAccount", t.Context(), AccountKeyFromParams(params)).Return(
		DerivedAddressAccount{
			AccountID:   42,
			AccountName: params.AccountName,
			IsDerived:   true,
		}, nil,
	).Once()

	deriveCalled := false
	deriveFn := func(context.Context,
		AddressDerivationParams) (*DerivedAddressData, error) {

		deriveCalled = true

		return &DerivedAddressData{}, nil
	}

	// Act: Attempt the count-one request with the malformed account metadata.
	addresses, exhausted, err := NewDerivedAddressesWithOps(
		t.Context(), params, 1, ops, deriveFn,
	)

	// Assert: Account corruption stops allocation without invoking derivation
	// or reporting exhaustion; only the account lookup was performed.
	require.ErrorIs(t, err, errAccountShapeCorruption)
	require.Nil(t, addresses)
	require.False(t, exhausted)
	require.False(t, deriveCalled)
	ops.AssertExpectations(t)
}

// TestDerivedAddressInputNilDerivedData verifies that the shared derivation
// path rejects a nil callback result before dereferencing it.
func TestDerivedAddressInputNilDerivedData(t *testing.T) {
	t.Parallel()

	// Arrange: Allocate one index, then return nil data without an error to
	// exercise validation of the callback result before row construction.
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
	ops.On("NextIndex", t.Context(), int64(1), false).Return(
		int64(7), nil,
	).Once()

	// Act: Prepare the child using the callback that omits its result data.
	addrType, branch, index, scriptPubKey, pubKey, err := derivedAddressInput(
		t.Context(), params, account, &accountNumber, ops, deriveFn,
	)

	// Assert: No partial derivation escapes, and the expected single counter
	// allocation is accounted for by the mock.
	require.Zero(t, addrType)
	require.Zero(t, branch)
	require.Zero(t, index)
	require.Nil(t, scriptPubKey)
	require.Nil(t, pubKey)
	require.ErrorIs(t, err, errNilDerivedAddressData)
	ops.AssertExpectations(t)
}
