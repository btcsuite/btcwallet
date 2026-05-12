package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCreateDerivedAccountParamsValidate verifies derived account creation
// validation rejects missing names.
func TestCreateDerivedAccountParamsValidate(t *testing.T) {
	t.Parallel()

	err := (&CreateDerivedAccountParams{Name: "default"}).Validate()
	require.NoError(t, err)

	err = (&CreateDerivedAccountParams{}).Validate()
	require.ErrorIs(t, err, ErrMissingAccountName)
}

// TestCreateImportedAccountParamsValidate verifies imported account creation
// validation rejects missing names and public keys.
func TestCreateImportedAccountParamsValidate(t *testing.T) {
	t.Parallel()

	err := (&CreateImportedAccountParams{
		Name:               "imported",
		EncryptedPublicKey: []byte{1},
	}).Validate()
	require.NoError(t, err)

	err = (&CreateImportedAccountParams{
		EncryptedPublicKey: []byte{1},
	}).Validate()
	require.ErrorIs(t, err, ErrMissingAccountName)

	err = (&CreateImportedAccountParams{Name: "imported"}).Validate()
	require.ErrorIs(t, err, ErrMissingAccountPublicKey)
}

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

// TestRenameAccountParamsValidate verifies account renames must include a new
// name and exactly one account selector.
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
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}
