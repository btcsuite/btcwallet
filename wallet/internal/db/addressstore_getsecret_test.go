package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGetAddressSecretQueryValidate verifies that an address-secret query
// accepts exactly one selector.
func TestGetAddressSecretQueryValidate(t *testing.T) {
	t.Parallel()

	addressID := uint32(1)

	tests := []struct {
		name       string
		query      GetAddressSecretQuery
		wantErr    error
		wantErrNil bool
	}{{
		name:    "nil script",
		query:   GetAddressSecretQuery{WalletID: 1},
		wantErr: ErrInvalidAddressQuery,
	}, {
		name: "empty script",
		query: GetAddressSecretQuery{
			WalletID:     1,
			ScriptPubKey: []byte{},
		},
		wantErr: ErrInvalidAddressQuery,
	}, {
		name: "address ID",
		query: GetAddressSecretQuery{
			WalletID:  1,
			AddressID: &addressID,
		},
		wantErrNil: true,
	}, {
		name: "populated script",
		query: GetAddressSecretQuery{
			WalletID:     1,
			ScriptPubKey: []byte{0x00, 0x14},
		},
		wantErrNil: true,
	}, {
		name: "both selectors",
		query: GetAddressSecretQuery{
			WalletID:     1,
			AddressID:    &addressID,
			ScriptPubKey: []byte{0x00, 0x14},
		},
		wantErr: ErrInvalidAddressQuery,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.query.Validate()
			if test.wantErrNil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, test.wantErr)
		})
	}
}
