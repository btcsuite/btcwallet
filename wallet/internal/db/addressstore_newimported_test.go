package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewImportedAddressParamsValidateWatchOnly verifies the watch-only
// direction of the imported-address invariant: a watch-only wallet rejects a
// private-key-bearing import, while a spendable wallet accepts any shape at
// this stage. The symmetric spendable-side requirement (a spendable wallet
// must carry spend material) is enforced separately by
// RequireAddressPrivKeyOnSpendable.
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
// invariant for imported addresses: a spendable wallet requires an address
// private key and rejects an import without one, while a watch-only wallet
// accepts a public-only import. ADR 0012 grants script-only imports no waiver
// on a spendable wallet.
func TestRequireAddressPrivKeyOnSpendable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		watchOnly     bool
		hasPrivKey    bool
		wantRejection bool
	}{
		{
			name:          "spendable public-only rejected",
			wantRejection: true,
		},
		{
			name:       "spendable private-key accepted",
			hasPrivKey: true,
		},
		{
			name:      "watch-only public-only accepted",
			watchOnly: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := RequireAddressPrivKeyOnSpendable(
				7, tc.watchOnly, tc.hasPrivKey,
			)

			if tc.wantRejection {
				require.ErrorIs(
					t, err,
					ErrSpendableWalletNeedsAddressPrivKey,
				)

				return
			}

			require.NoError(t, err)
		})
	}
}
