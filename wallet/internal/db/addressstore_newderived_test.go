package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mockNewDerivedAddressOps is a configurable db.NewDerivedAddressOps stub for
// exercising the shared derived-address workflow. Unset fields panic if called,
// so each test only wires the methods its path reaches.
type mockNewDerivedAddressOps struct {
	getAccount func(context.Context,
		AccountLookupKey) (DerivedAddressAccount, error)
	nextIndex  func(context.Context, int64, bool) (int64, error)
	createAddr func(context.Context,
		CreateDerivedAddressRequest) (CreateDerivedAddressRow, error)
}

var _ NewDerivedAddressOps = mockNewDerivedAddressOps{}

func (m mockNewDerivedAddressOps) GetAccount(ctx context.Context,
	key AccountLookupKey) (DerivedAddressAccount, error) {

	return m.getAccount(ctx, key)
}

func (m mockNewDerivedAddressOps) NextIndex(ctx context.Context,
	accountID int64, change bool) (int64, error) {

	return m.nextIndex(ctx, accountID, change)
}

func (m mockNewDerivedAddressOps) CreateDerivedAddress(ctx context.Context,
	req CreateDerivedAddressRequest) (CreateDerivedAddressRow, error) {

	return m.createAddr(ctx, req)
}

// TestNewDerivedAddressWithOpsNilDeriveFn verifies that the shared workflow
// rejects a missing derivation callback before touching the backend adapter.
func TestNewDerivedAddressWithOpsNilDeriveFn(t *testing.T) {
	t.Parallel()

	_, err := NewDerivedAddressWithOps(
		t.Context(), NewDerivedAddressParams{}, mockNewDerivedAddressOps{}, nil,
	)
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

	ops := mockNewDerivedAddressOps{
		getAccount: func(_ context.Context,
			key AccountLookupKey) (DerivedAddressAccount, error) {

			require.Equal(t, int64(params.WalletID), key.WalletID)
			require.Equal(t, int64(params.Scope.Purpose), key.Purpose)
			require.Equal(t, int64(params.Scope.Coin), key.CoinType)
			require.Equal(t, params.AccountName, key.AccountName)

			return account, nil
		},
		nextIndex: func(_ context.Context, accountID int64,
			change bool) (int64, error) {

			require.Equal(t, int64(42), accountID)
			require.False(t, change)

			return 5, nil
		},
		createAddr: func(_ context.Context,
			req CreateDerivedAddressRequest) (CreateDerivedAddressRow, error) {

			require.Equal(t, int64(params.WalletID), req.WalletID)
			require.Equal(t, int64(42), req.AccountID)
			require.Equal(t, WitnessPubKey, req.AddrType)
			require.Zero(t, req.Branch)
			require.Equal(t, uint32(5), req.Index)
			require.Equal(t, []byte{1}, req.ScriptPubKey)
			require.Equal(t, []byte{2}, req.PubKey)

			return CreateDerivedAddressRow{ID: 99, CreatedAt: now}, nil
		},
	}

	deriveFn := func(_ context.Context, p AddressDerivationParams) (
		*DerivedAddressData, error) {

		require.Equal(t, uint32(3), *p.DerivedAccountNumber)
		require.Equal(t, uint32(5), p.Index)

		return &DerivedAddressData{
			ScriptPubKey: []byte{1},
			PubKey:       []byte{2},
		}, nil
	}

	info, err := NewDerivedAddressWithOps(t.Context(), params, ops, deriveFn)
	require.NoError(t, err)
	require.Equal(t, uint32(99), info.ID)
	require.Equal(t, params.AccountName, info.AccountName)
	require.Equal(t, params.Scope, info.KeyScope)
	require.Equal(t, uint32(3), *info.AccountNumber)
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

	ops := mockNewDerivedAddressOps{
		getAccount: func(context.Context,
			AccountLookupKey) (DerivedAddressAccount, error) {

			// AccountNumber left invalid (NULL) while IsDerived is true.
			return DerivedAddressAccount{
				AccountID:   42,
				AccountName: params.AccountName,
				IsDerived:   true,
			}, nil
		},
	}
	deriveFn := func(context.Context,
		AddressDerivationParams) (*DerivedAddressData, error) {

		deriveCalled = true

		return &DerivedAddressData{}, nil
	}

	_, err := NewDerivedAddressWithOps(t.Context(), params, ops, deriveFn)
	require.ErrorIs(t, err, errAccountShapeCorruption)
	require.False(t, deriveCalled)
}

// TestDerivedAddressInputNilDerivedData verifies that the shared derivation
// path rejects a nil callback result before dereferencing it.
func TestDerivedAddressInputNilDerivedData(t *testing.T) {
	t.Parallel()

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
	ops := mockNewDerivedAddressOps{
		nextIndex: func(context.Context, int64, bool) (int64, error) {
			return 7, nil
		},
	}

	addrType, branch, index, scriptPubKey, pubKey, err := derivedAddressInput(
		t.Context(), params, account, &accountNumber, ops, deriveFn,
	)

	require.Zero(t, addrType)
	require.Zero(t, branch)
	require.Zero(t, index)
	require.Nil(t, scriptPubKey)
	require.Nil(t, pubKey)
	require.ErrorIs(t, err, errNilDerivedAddressData)
}
