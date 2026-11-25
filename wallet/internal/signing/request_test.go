package signing

import (
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// TestDigestRequestValidate verifies that a request is valid only with a
// selector that names a key and a known signature mode, so vault
// implementations can reject it before they read any secret.
func TestDigestRequestValidate(t *testing.T) {
	t.Parallel()

	derived := DerivedKey{KeyScope: waddrmgr.KeyScopeBIP0084}
	imported := ImportedKey{ScriptPubKey: []byte{0x51}}

	tests := []struct {
		name    string
		req     DigestRequest
		wantErr error
	}{
		{
			name: "derived ecdsa",
			req:  DigestRequest{Key: derived, Mode: ModeECDSA},
		},
		{
			name: "imported compact ecdsa",
			req:  DigestRequest{Key: imported, Mode: ModeCompactECDSA},
		},
		{
			name: "schnorr",
			req:  DigestRequest{Key: derived, Mode: ModeSchnorr},
		},
		{
			name:    "missing key",
			req:     DigestRequest{Mode: ModeECDSA},
			wantErr: ErrInvalidKeySelector,
		},
		{
			name:    "typed nil key",
			req:     DigestRequest{Key: (*DerivedKey)(nil), Mode: ModeECDSA},
			wantErr: ErrInvalidKeySelector,
		},
		{
			name:    "pointer key",
			req:     DigestRequest{Key: &derived, Mode: ModeECDSA},
			wantErr: ErrInvalidKeySelector,
		},
		{
			name:    "invalid key",
			req:     DigestRequest{Key: ImportedKey{}, Mode: ModeECDSA},
			wantErr: ErrInvalidKeySelector,
		},
		{
			name:    "zero mode",
			req:     DigestRequest{Key: derived},
			wantErr: ErrInvalidMode,
		},
		{
			name:    "unknown mode",
			req:     DigestRequest{Key: derived, Mode: ModeSchnorr + 1},
			wantErr: ErrInvalidMode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Act: Validate the request.
			err := test.req.Validate()

			// Assert: Only the expected field is refused.
			require.ErrorIs(t, err, test.wantErr)
		})
	}
}
