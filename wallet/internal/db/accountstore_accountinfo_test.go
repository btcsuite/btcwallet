package db

import (
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// TestAccountRowToInfoPopulatesAddrSchema verifies SQL account rows expose the
// effective key-scope address schema on AccountInfo, including the schema
// values returned by AccountRowToInfo.
func TestAccountRowToInfoPopulatesAddrSchema(t *testing.T) {
	t.Parallel()

	row := AccountInfoRow[int16]{
		RowID:            42,
		AccountNumber:    sql.NullInt64{Int64: 7, Valid: true},
		AccountName:      "strict",
		IsDerived:        true,
		ExternalKeyCount: 1,
		InternalKeyCount: 2,
		CreatedAt:        time.Unix(123, 0).UTC(),
		Purpose:          49,
		CoinType:         0,
		InternalTypeID:   int16(NestedWitnessPubKey),
		ExternalTypeID:   int16(NestedWitnessPubKey),
	}

	info, err := AccountRowToInfo(row)
	require.NoError(t, err)
	require.Equal(t, ScopeAddrSchema{
		ExternalAddrType: NestedWitnessPubKey,
		InternalAddrType: NestedWitnessPubKey,
	}, info.AddrSchema)
	require.Equal(t, int64(42), info.rowID)
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
