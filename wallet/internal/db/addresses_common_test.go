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

// TestNewImportedAddressParamsValidateWatchOnly verifies the symmetric
// watch-only invariant rejects mismatched mode imports in both directions
// for imported addresses. A script-only import (no priv key, has script) is
// rejected in a spendable wallet because the spend-capability invariant
// requires private-key material per ADR 0012.
func TestNewImportedAddressParamsValidateWatchOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		encryptedPrivKey []byte
		encryptedScript  []byte
		walletWatchOnly  bool
		wantErr          error
	}{
		{
			name:             "watch-only wallet rejects priv key",
			encryptedPrivKey: []byte{1},
			walletWatchOnly:  true,
			wantErr:          ErrWatchOnlyViolation,
		},
		{
			name:            "watch-only wallet accepts public-only",
			walletWatchOnly: true,
		},
		{
			name:             "spendable wallet accepts priv key",
			encryptedPrivKey: []byte{1},
			walletWatchOnly:  false,
		},
		{
			name:            "spendable wallet accepts public-only (kvdb path)",
			walletWatchOnly: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			params := NewImportedAddressParams{
				WalletID:            7,
				EncryptedPrivateKey: tc.encryptedPrivKey,
				EncryptedScript:     tc.encryptedScript,
			}
			err := params.ValidateWatchOnly(tc.walletWatchOnly)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}

// TestRequireAddressPrivKeyOnSpendable verifies the SQL-only symmetric
// rejection for imported addresses. Public-only AND script-only imports are
// rejected in spendable wallets because both lack the encrypted private-key
// material that ADR 0012 requires.
func TestRequireAddressPrivKeyOnSpendable(t *testing.T) {
	t.Parallel()

	err := RequireAddressPrivKeyOnSpendable(7, false, false)
	require.ErrorIs(t, err, ErrSpendableWalletNeedsAddressPrivKey)

	err = RequireAddressPrivKeyOnSpendable(7, false, true)
	require.NoError(t, err)

	err = RequireAddressPrivKeyOnSpendable(7, true, false)
	require.NoError(t, err)
}
