package db

import (
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// TestCreateImportedAccountParamsValidate verifies imported account creation
// validation rejects missing names and public keys.
func TestCreateImportedAccountParamsValidate(t *testing.T) {
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
			require.ErrorIs(t, err, test.wantErr)
		})
	}
}

// TestAccountRowToInfoPopulatesAddrSchema verifies SQL account rows expose the
// effective key-scope address schema on AccountInfo.
func TestAccountRowToInfoPopulatesAddrSchema(t *testing.T) {
	t.Parallel()

	row := AccountInfoRow[int16]{
		AccountNumber:    sql.NullInt64{Int64: 7, Valid: true},
		AccountName:      "strict",
		OriginID:         int16(ImportedAccount),
		ExternalKeyCount: 1,
		InternalKeyCount: 2,
		ImportedKeyCount: 3,
		CreatedAt:        time.Unix(123, 0).UTC(),
		Purpose:          49,
		CoinType:         0,
		InternalTypeID:   int16(NestedWitnessPubKey),
		ExternalTypeID:   int16(NestedWitnessPubKey),
		IDToOriginType:   IDToAccountOrigin[int16],
	}

	info, err := AccountRowToInfo(row)
	require.NoError(t, err)
	require.Equal(t, ScopeAddrSchema{
		ExternalAddrType: NestedWitnessPubKey,
		InternalAddrType: NestedWitnessPubKey,
	}, info.AddrSchema)
}

// TestScopeAddrSchemaFromWaddrmgr verifies legacy address-manager schemas are
// converted into the database account schema shape.
func TestScopeAddrSchemaFromWaddrmgr(t *testing.T) {
	t.Parallel()

	schema, err := ScopeAddrSchemaFromWaddrmgr(waddrmgr.ScopeAddrSchema{
		ExternalAddrType: waddrmgr.NestedWitnessPubKey,
		InternalAddrType: waddrmgr.WitnessPubKey,
	})
	require.NoError(t, err)
	require.Equal(t, ScopeAddrSchema{
		ExternalAddrType: NestedWitnessPubKey,
		InternalAddrType: WitnessPubKey,
	}, schema)

	// BIP44 schemas (waddrmgr.PubKeyHash external + waddrmgr.PubKeyHash
	// internal) regression test for the enum-ordinal mismatch.
	schema, err = ScopeAddrSchemaFromWaddrmgr(waddrmgr.ScopeAddrSchema{
		ExternalAddrType: waddrmgr.PubKeyHash,
		InternalAddrType: waddrmgr.PubKeyHash,
	})
	require.NoError(t, err)
	require.Equal(t, ScopeAddrSchema{
		ExternalAddrType: PubKeyHash,
		InternalAddrType: PubKeyHash,
	}, schema)
}
