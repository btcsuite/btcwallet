package signing

import (
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// TestValidateKeySelector verifies that only DerivedKey and ImportedKey values
// that name a key are accepted: an import needs its script pubkey, and a nil
// selector or a pointer to either type, nil or not, names no key.
func TestValidateKeySelector(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sel     KeySelector
		wantErr error
	}{
		{
			name: "derived",
			sel:  DerivedKey{KeyScope: waddrmgr.KeyScopeBIP0084},
		},
		{
			name: "imported",
			sel:  ImportedKey{ScriptPubKey: []byte{0x51}},
		},
		{
			name:    "empty import script",
			sel:     ImportedKey{},
			wantErr: ErrInvalidKeySelector,
		},
		{
			name:    "nil selector",
			sel:     nil,
			wantErr: ErrInvalidKeySelector,
		},
		{
			name:    "nil derived pointer",
			sel:     (*DerivedKey)(nil),
			wantErr: ErrInvalidKeySelector,
		},
		{
			name:    "nil imported pointer",
			sel:     (*ImportedKey)(nil),
			wantErr: ErrInvalidKeySelector,
		},
		{
			name:    "derived pointer",
			sel:     &DerivedKey{},
			wantErr: ErrInvalidKeySelector,
		},
		{
			name:    "imported pointer",
			sel:     &ImportedKey{ScriptPubKey: []byte{0x51}},
			wantErr: ErrInvalidKeySelector,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Act: Validate the selector.
			err := ValidateKeySelector(test.sel)

			// Assert: Only valid selector values are accepted.
			require.ErrorIs(t, err, test.wantErr)
		})
	}
}
