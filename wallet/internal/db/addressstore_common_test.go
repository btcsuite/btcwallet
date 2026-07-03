package db

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestAddressRowToInfoRejectsWalletDerivedWithoutPath verifies that a
// wallet-seed-derived address parent row must have a derived_addresses child.
func TestAddressRowToInfoRejectsWalletDerivedWithoutPath(t *testing.T) {
	t.Parallel()

	_, err := AddressRowToInfo(AddressInfoRow[int64]{
		ID:           1,
		TypeID:       int64(WitnessPubKey),
		IsDerived:    true,
		ScriptPubKey: []byte{0x51},
		CreatedAt:    time.Unix(1710006000, 0),
		IDToAddrType: func(int64) (AddressType, error) {
			return WitnessPubKey, nil
		},
	})
	require.ErrorIs(t, err, errAddressShapeCorruption)
}

// TestAddressRowToInfoRejectsImportedAccountNumber verifies that imported-xpub
// addresses cannot expose a BIP44 account number from corrupt account metadata.
func TestAddressRowToInfoRejectsImportedAccountNumber(t *testing.T) {
	t.Parallel()

	_, err := AddressRowToInfo(AddressInfoRow[int64]{
		ID:               1,
		DerivedAddressID: sqlNullInt64(1),
		AccountID:        sqlNullInt64(2),
		AccountNumber:    sqlNullInt64(3),
		AccountName:      sqlNullString("hardware"),
		Purpose:          sqlNullInt64(int64(KeyScopeBIP0084.Purpose)),
		CoinType:         sqlNullInt64(int64(KeyScopeBIP0084.Coin)),
		TypeID:           int64(WitnessPubKey),
		IsDerived:        true,
		AccountIsDerived: sql.NullBool{
			Bool:  false,
			Valid: true,
		},
		ScriptPubKey:  []byte{0x51},
		CreatedAt:     time.Unix(1710006001, 0),
		AddressBranch: sqlNullInt64(0),
		AddressIndex:  sqlNullInt64(0),
		IDToAddrType: func(int64) (AddressType, error) {
			return WitnessPubKey, nil
		},
	})
	require.ErrorIs(t, err, errAccountShapeCorruption)
}

// sqlNullInt64 creates a valid nullable integer for address conversion tests.
func sqlNullInt64(value int64) sql.NullInt64 {
	return sql.NullInt64{Int64: value, Valid: true}
}

// sqlNullString creates a valid nullable string for address conversion tests.
func sqlNullString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: true}
}
