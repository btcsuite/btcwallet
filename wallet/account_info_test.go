// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/addresstype"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestAccountInfoFromDBConvertsFields verifies every store field exposed by
// the public account snapshot is converted without losing its value.
func TestAccountInfoFromDBConvertsFields(t *testing.T) {
	t.Parallel()

	accountNumber := uint32(7)
	createdAt := time.Date(2026, time.August, 20, 12, 30, 0, 0, time.UTC)
	stored := db.AccountInfo{
		AccountNumber:      &accountNumber,
		AccountName:        "derived account",
		ExternalKeyCount:   11,
		InternalKeyCount:   13,
		ImportedKeyCount:   17,
		ConfirmedBalance:   btcutil.Amount(19),
		UnconfirmedBalance: btcutil.Amount(23),
		IsWatchOnly:        true,
		CreatedAt:          createdAt,
		KeyScope:           db.KeyScope{Purpose: 49, Coin: 1},
		AddrSchema: db.ScopeAddrSchema{
			ExternalAddrType: db.NestedWitnessPubKey,
			InternalAddrType: db.WitnessPubKey,
		},
		PublicKey:            []byte("xpub"),
		MasterKeyFingerprint: 0x01020304,
	}
	wantAccountNumber := AccountNumber(7)
	wantFingerprint := MasterFingerprint(0x01020304)
	want := AccountInfo{
		AccountNumber:      &wantAccountNumber,
		AccountName:        "derived account",
		ExternalKeyCount:   11,
		InternalKeyCount:   13,
		ImportedKeyCount:   17,
		ConfirmedBalance:   btcutil.Amount(19),
		UnconfirmedBalance: btcutil.Amount(23),
		IsWatchOnly:        true,
		CreatedAt:          createdAt,
		KeyScope:           waddrmgr.KeyScope{Purpose: 49, Coin: 1},
		AddrSchema: waddrmgr.ScopeAddrSchema{
			ExternalAddrType: waddrmgr.NestedWitnessPubKey,
			InternalAddrType: waddrmgr.WitnessPubKey,
		},
		PublicKey:            []byte("xpub"),
		MasterKeyFingerprint: &wantFingerprint,
	}

	got, err := accountInfoFromDB(stored)

	require.NoError(t, err)
	require.Equal(t, want, got)
}

// TestAccountInfoFromDBPreservesOptionalValues verifies account-number absence
// and present-zero values survive conversion without ambiguous test controls.
func TestAccountInfoFromDBPreservesOptionalValues(t *testing.T) {
	t.Parallel()

	zeroAccountNumber := uint32(0)
	wantZeroAccountNumber := AccountNumber(0)
	tests := []struct {
		name                  string
		accountNumber         *uint32
		isImported            bool
		masterFingerprint     uint32
		wantAccountNumber     *AccountNumber
		wantMasterFingerprint MasterFingerprint
	}{
		{
			name: "absent account number and " +
				"zero fingerprint",
			masterFingerprint:     0,
			wantAccountNumber:     nil,
			wantMasterFingerprint: MasterFingerprint(0),
		},
		{
			name: "present zero account and " +
				"nonzero fingerprint",
			accountNumber:         &zeroAccountNumber,
			isImported:            true,
			masterFingerprint:     123,
			wantAccountNumber:     &wantZeroAccountNumber,
			wantMasterFingerprint: MasterFingerprint(123),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := accountInfoFromDB(db.AccountInfo{
				AccountNumber: test.accountNumber,
				IsImported:    test.isImported,
				AddrSchema: db.ScopeAddrSchema{
					ExternalAddrType: db.WitnessPubKey,
					InternalAddrType: db.WitnessPubKey,
				},
				MasterKeyFingerprint: test.masterFingerprint,
			})

			require.NoError(t, err)
			require.Equal(
				t, test.wantAccountNumber, got.AccountNumber,
			)
			require.Equal(t, test.isImported, got.IsImported)
			wantFingerprint := test.wantMasterFingerprint
			require.Equal(
				t, wantFingerprint, *got.MasterKeyFingerprint,
			)
		})
	}
}

// TestAccountInfoFromDBCopiesMutableFields verifies independently converted
// results do not share pointers or byte slices with the store or each other.
func TestAccountInfoFromDBCopiesMutableFields(t *testing.T) {
	t.Parallel()

	accountNumber := uint32(7)
	stored := db.AccountInfo{
		AccountNumber: &accountNumber,
		AddrSchema: db.ScopeAddrSchema{
			ExternalAddrType: db.WitnessPubKey,
			InternalAddrType: db.WitnessPubKey,
		},
		PublicKey:            []byte("xpub"),
		MasterKeyFingerprint: 42,
	}

	first, err := accountInfoFromDB(stored)
	require.NoError(t, err)
	second, err := accountInfoFromDB(stored)
	require.NoError(t, err)

	*first.AccountNumber = 8
	first.PublicKey[0] = 'X'
	*first.MasterKeyFingerprint = 99

	require.Equal(t, uint32(7), *stored.AccountNumber)
	require.Equal(t, []byte("xpub"), stored.PublicKey)
	require.Equal(t, uint32(42), stored.MasterKeyFingerprint)
	require.Equal(t, AccountNumber(7), *second.AccountNumber)
	require.Equal(t, []byte("xpub"), second.PublicKey)
	require.Equal(t, MasterFingerprint(42), *second.MasterKeyFingerprint)
}

// TestAccountInfoFromDBRejectsUnsupportedAddrSchema verifies unsupported
// address types prevent a partial public result.
func TestAccountInfoFromDBRejectsUnsupportedAddrSchema(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		schema db.ScopeAddrSchema
	}{
		{
			name: "unsupported external type",
			schema: db.ScopeAddrSchema{
				ExternalAddrType: db.Anchor,
				InternalAddrType: db.WitnessPubKey,
			},
		},
		{
			name: "unsupported internal type",
			schema: db.ScopeAddrSchema{
				ExternalAddrType: db.WitnessPubKey,
				InternalAddrType: db.Anchor,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := accountInfoFromDB(db.AccountInfo{
				AddrSchema: test.schema,
			})

			require.ErrorIs(t, err, addresstype.ErrUnknown)
			require.Equal(t, AccountInfo{}, got)
		})
	}
}

// TestAccountInfosFromDBPreservesSliceShape verifies nil and non-nil empty
// store results retain their distinct slice shapes.
func TestAccountInfosFromDBPreservesSliceShape(t *testing.T) {
	t.Parallel()

	var nilStored []db.AccountInfo

	got, err := accountInfosFromDB(nilStored)
	require.NoError(t, err)
	require.Nil(t, got)

	emptyStored := []db.AccountInfo{}
	got, err = accountInfosFromDB(emptyStored)
	require.NoError(t, err)
	require.Equal(t, []AccountInfo{}, got)
}

// TestAccountInfosFromDBReturnsConversionError verifies list conversion does
// not return a partial result when one account has an unsupported address type.
func TestAccountInfosFromDBReturnsConversionError(t *testing.T) {
	t.Parallel()

	got, err := accountInfosFromDB([]db.AccountInfo{
		{
			AddrSchema: db.ScopeAddrSchema{
				ExternalAddrType: db.WitnessPubKey,
				InternalAddrType: db.WitnessPubKey,
			},
		},
		// Anchor has no wallet-facing address type, so this row must
		// fail conversion.
		{
			AddrSchema: db.ScopeAddrSchema{
				ExternalAddrType: db.Anchor,
				InternalAddrType: db.WitnessPubKey,
			},
		},
	})

	require.ErrorIs(t, err, addresstype.ErrUnknown)
	require.Nil(t, got)
}
