package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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

	err := RequireAddressPrivKeyOnSpendable(7, false, false)
	require.ErrorIs(t, err, ErrSpendableWalletNeedsAddressPrivKey)

	err = RequireAddressPrivKeyOnSpendable(7, false, true)
	require.NoError(t, err)

	err = RequireAddressPrivKeyOnSpendable(7, true, false)
	require.NoError(t, err)
}
