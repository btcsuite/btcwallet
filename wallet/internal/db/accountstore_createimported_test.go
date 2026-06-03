package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCreateImportedAccountParamsValidateBasic verifies imported account
// creation validation rejects missing account names and public keys.
func TestCreateImportedAccountParamsValidateBasic(t *testing.T) {
	t.Parallel()

	err := (&CreateImportedAccountParams{
		Name:      "imported",
		PublicKey: []byte{1},
	}).ValidateBasic()
	require.NoError(t, err)

	err = (&CreateImportedAccountParams{
		PublicKey: []byte{1},
	}).ValidateBasic()
	require.ErrorIs(t, err, ErrMissingAccountName)

	err = (&CreateImportedAccountParams{Name: "imported"}).ValidateBasic()
	require.ErrorIs(t, err, ErrMissingAccountPublicKey)
}
