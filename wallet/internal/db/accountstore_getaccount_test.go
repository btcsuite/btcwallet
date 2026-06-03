package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGetAccountQueryValidate verifies account lookups must use exactly one
// account selector.
func TestGetAccountQueryValidate(t *testing.T) {
	t.Parallel()

	name := "default"
	accountNumber := uint32(7)

	tests := []struct {
		name    string
		query   GetAccountQuery
		wantErr error
	}{
		{
			name:  "name selector",
			query: GetAccountQuery{Name: &name},
		},
		{
			name:  "number selector",
			query: GetAccountQuery{AccountNumber: &accountNumber},
		},
		{
			name:    "no selector",
			query:   GetAccountQuery{},
			wantErr: ErrInvalidAccountQuery,
		},
		{
			name: "both selectors",
			query: GetAccountQuery{
				Name:          &name,
				AccountNumber: &accountNumber,
			},
			wantErr: ErrInvalidAccountQuery,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.query.Validate()
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}
