package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewDerivedAddressWithTxNilDeriveFn verifies that the shared helper
// rejects a missing derivation callback before opening a transaction.
func TestNewDerivedAddressWithTxNilDeriveFn(t *testing.T) {
	t.Parallel()

	executed := false

	_, err := NewDerivedAddressWithTx(
		t.Context(), NewDerivedAddressParams{},
		func(context.Context, func(struct{}) error) error {
			executed = true

			return nil
		},
		DerivedAddressAdapters[struct{}, struct{}, struct{}, struct{}]{}, nil,
	)

	require.False(t, executed)
	require.ErrorIs(t, err, errNilAddressDerivationFunc)
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

	addrType, branch, index, scriptPubKey, pubKey, err :=
		derivedAddressInput(
			t.Context(), params, 1, 0,
			ScopeAddrSchema{
				ExternalAddrType: PubKeyHash,
				InternalAddrType: PubKeyHash,
			}, nil,
			func(context.Context, int64) (int64, error) {
				return 7, nil
			},
			func(context.Context, int64) (int64, error) {
				return 11, nil
			}, deriveFn,
		)

	require.Zero(t, addrType)
	require.Zero(t, branch)
	require.Zero(t, index)
	require.Nil(t, scriptPubKey)
	require.Nil(t, pubKey)
	require.ErrorIs(t, err, errNilDerivedAddressData)
}
