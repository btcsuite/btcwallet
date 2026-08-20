package db

import (
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
		DerivedAddressID: presentInt64(1),
		AccountID:        presentInt64(2),
		AccountNumber:    presentInt64(3),
		AccountName:      presentString("hardware"),
		Purpose:          presentInt64(int64(KeyScopeBIP0084.Purpose)),
		CoinType:         presentInt64(int64(KeyScopeBIP0084.Coin)),
		TypeID:           int64(WitnessPubKey),
		IsDerived:        true,
		AccountIsDerived: NewNullable(false),
		ScriptPubKey:     []byte{0x51},
		CreatedAt:        time.Unix(1710006001, 0),
		AddressBranch:    presentInt64(0),
		AddressIndex:     presentInt64(0),
		IDToAddrType: func(int64) (AddressType, error) {
			return WitnessPubKey, nil
		},
	})
	require.ErrorIs(t, err, errAccountShapeCorruption)
}

// presentInt64 creates a present nullable integer for address conversion tests.
func presentInt64(value int64) Nullable[int64] {
	return NewNullable(value)
}

// presentString creates a present nullable string for address conversion tests.
func presentString(value string) Nullable[string] {
	return NewNullable(value)
}
