package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewImportedAddressParamsValidateWatchOnly verifies the watch-only
// direction of the imported-address invariant: a watch-only wallet rejects a
// private-key-bearing import, while a spendable wallet accepts any shape at
// this stage. Public material remains watch-only without an account owner.
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
			name:            "spendable wallet accepts public-only",
			walletWatchOnly: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: bind the case's encrypted material and parent custody
			// directly, isolating admission from backend persistence.
			params := NewImportedAddressParams{
				WalletID:            7,
				EncryptedPrivateKey: tc.encryptedPrivKey,
				EncryptedScript:     tc.encryptedScript,
			}

			// Act: validate only the parent/private-material custody rule.
			err := params.ValidateWatchOnly(tc.walletWatchOnly)

			// Assert: private material is refused under a watch-only parent;
			// the signing and public-only controls remain admitted.
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}
