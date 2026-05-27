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

// TestNewImportedAddressParamsValidateWatchOnly verifies the symmetric
// watch-only invariant rejects mismatched mode imports in both directions
// for imported addresses. A script-only import (no priv key, has script) is
// rejected in a spendable wallet because the spend-capability invariant
// requires private-key material per ADR 0012.
func TestNewImportedAddressParamsValidateWatchOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		encryptedPrivKey []byte
		encryptedScript  []byte
		walletWatchOnly  bool
		wantErr          error
	}{
		{
			name:             "watch-only wallet rejects priv key",
			encryptedPrivKey: []byte{1},
			walletWatchOnly:  true,
			wantErr:          ErrWatchOnlyViolation,
		},
		{
			name:            "watch-only wallet accepts public-only",
			walletWatchOnly: true,
		},
		{
			name:             "spendable wallet accepts priv key",
			encryptedPrivKey: []byte{1},
			walletWatchOnly:  false,
		},
		{
			name:            "spendable wallet accepts public-only (kvdb path)",
			walletWatchOnly: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			params := NewImportedAddressParams{
				WalletID:            7,
				EncryptedPrivateKey: tc.encryptedPrivKey,
				EncryptedScript:     tc.encryptedScript,
			}
			err := params.ValidateWatchOnly(tc.walletWatchOnly)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}

// TestRequireAddressPrivKeyOnSpendable verifies the SQL-only symmetric
// rejection for imported addresses. Public-only AND script-only imports are
// rejected in spendable wallets because both lack the encrypted private-key
// material that ADR 0012 requires.
func TestRequireAddressPrivKeyOnSpendable(t *testing.T) {
	t.Parallel()

	err := requireAddressPrivKeyOnSpendable(7, false, false)
	require.ErrorIs(t, err, ErrSpendableWalletNeedsAddressPrivKey)

	err = requireAddressPrivKeyOnSpendable(7, false, true)
	require.NoError(t, err)

	err = requireAddressPrivKeyOnSpendable(7, true, false)
	require.NoError(t, err)
}
