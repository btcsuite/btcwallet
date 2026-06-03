package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRenameAccountParamsValidate verifies account renames must include a new
// name and exactly one account selector. Table-driven cases cover both valid
// selectors and the invalid combinations.
func TestRenameAccountParamsValidate(t *testing.T) {
	t.Parallel()

	accountNumber := uint32(7)

	tests := []struct {
		name    string
		params  RenameAccountParams
		wantErr error
	}{
		{
			name: "old name selector",
			params: RenameAccountParams{
				OldName: "default",
				NewName: "renamed",
			},
		},
		{
			name: "account number selector",
			params: RenameAccountParams{
				AccountNumber: &accountNumber,
				NewName:       "renamed",
			},
		},
		{
			name: "missing new name",
			params: RenameAccountParams{
				OldName: "default",
			},
			wantErr: ErrMissingAccountName,
		},
		{
			name: "no selector",
			params: RenameAccountParams{
				NewName: "renamed",
			},
			wantErr: ErrInvalidAccountQuery,
		},
		{
			name: "both selectors",
			params: RenameAccountParams{
				OldName:       "default",
				AccountNumber: &accountNumber,
				NewName:       "renamed",
			},
			wantErr: ErrInvalidAccountQuery,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.params.Validate()
			require.ErrorIs(t, err, test.wantErr)
		})
	}
}
