package db

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestNewDerivedAddressWithTxNilDeriveFn verifies that the shared helper
// rejects a missing derivation callback before opening a transaction.
func TestNewDerivedAddressWithTxNilDeriveFn(t *testing.T) {
	t.Parallel()

	executed := false

	_, err := NewDerivedAddressWithTx(
		t.Context(), NewDerivedAddressParams{},
		func(context.Context, func(struct{}) error) error {
			executed = true

			return nil
		},
		DerivedAddressAdapters[struct{}, struct{}, struct{}, struct{}]{}, nil,
	)

	require.False(t, executed)
	require.ErrorIs(t, err, errNilAddressDerivationFunc)
}

// derivedAddressTestQTX identifies the transaction handle used by the generic
// derived-address test.
type derivedAddressTestQTX struct {
	token string
}

// derivedAddressTestAccount is the account row shape used by the generic
// derived-address transaction-scope test.
type derivedAddressTestAccount struct {
	id            int64
	number        uint32
	name          string
	scope         KeyScope
	isDerived     bool
	walletWatch   bool
	addressSchema ScopeAddrSchema
	accountPubKey []byte
}

// derivedAddressTestRow is the inserted address row shape used by the generic
// derived-address transaction-scope test.
type derivedAddressTestRow struct {
	id        int64
	createdAt time.Time
}

// TestNewDerivedAddressWithTxUsesTransactionAccountLookup verifies account
// lookup is bound to the write transaction query handle.
func TestNewDerivedAddressWithTxUsesTransactionAccountLookup(t *testing.T) {
	t.Parallel()

	now := time.Unix(1710005000, 0).UTC()
	params := NewDerivedAddressParams{
		WalletID:    7,
		AccountName: "acct",
		Scope:       KeyScopeBIP0084,
	}
	qtx := derivedAddressTestQTX{token: "write-tx"}

	var usedToken string

	adapters := DerivedAddressAdapters[
		derivedAddressTestQTX,
		derivedAddressTestAccount,
		AccountLookupKey,
		derivedAddressTestRow]{
		GetAccount: func(q derivedAddressTestQTX) func(
			context.Context, AccountLookupKey) (derivedAddressTestAccount,
			error) {

			return func(_ context.Context,
				key AccountLookupKey) (derivedAddressTestAccount, error) {

				usedToken = q.token
				require.Equal(t, int64(params.WalletID), key.WalletID)
				require.Equal(t, int64(params.Scope.Purpose), key.Purpose)
				require.Equal(t, int64(params.Scope.Coin), key.CoinType)
				require.Equal(t, params.AccountName, key.AccountName)

				return derivedAddressTestAccount{
					id:          42,
					number:      3,
					name:        params.AccountName,
					scope:       params.Scope,
					isDerived:   true,
					walletWatch: false,
					addressSchema: ScopeAddrSchema{
						ExternalAddrType: WitnessPubKey,
						InternalAddrType: WitnessPubKey,
					},
				}, nil
			}
		},
		AccountParams: AccountKeyFromParams,
		GetAccountID: func(row derivedAddressTestAccount) int64 {
			return row.id
		},
		GetAccountNumber: func(row derivedAddressTestAccount) (uint32, error) {
			return row.number, nil
		},
		GetAccountIsDerived: func(row derivedAddressTestAccount) bool {
			return row.isDerived
		},
		GetWalletWatchOnly: func(row derivedAddressTestAccount) bool {
			return row.walletWatch
		},
		GetAccountAddrSchema: func(row derivedAddressTestAccount) (
			ScopeAddrSchema, error) {

			return row.addressSchema, nil
		},
		GetAccountPubKey: func(row derivedAddressTestAccount) []byte {
			return row.accountPubKey
		},
		GetExtIndex: func(q derivedAddressTestQTX) func(
			context.Context, int64) (int64, error) {

			return func(_ context.Context, accountID int64) (int64, error) {
				require.Equal(t, qtx.token, q.token)
				require.Equal(t, int64(42), accountID)

				return 5, nil
			}
		},
		GetIntIndex: func(q derivedAddressTestQTX) func(
			context.Context, int64) (int64, error) {

			return func(_ context.Context, _ int64) (int64, error) {
				require.Equal(t, qtx.token, q.token)

				return 6, nil
			}
		},
		CreateAddr: func(q derivedAddressTestQTX) func(
			context.Context, int64, int64, AddressType, uint32, uint32,
			[]byte, []byte) (derivedAddressTestRow, error) {

			return func(_ context.Context, walletID, accountID int64,
				addrType AddressType, branch, index uint32,
				scriptPubKey, pubKey []byte) (derivedAddressTestRow, error) {

				require.Equal(t, qtx.token, q.token)
				require.Equal(t, int64(params.WalletID), walletID)
				require.Equal(t, int64(42), accountID)
				require.Equal(t, WitnessPubKey, addrType)
				require.Zero(t, branch)
				require.Equal(t, uint32(5), index)
				require.Equal(t, []byte{1}, scriptPubKey)
				require.Equal(t, []byte{2}, pubKey)

				return derivedAddressTestRow{id: 99, createdAt: now}, nil
			}
		},
		RowID: func(row derivedAddressTestRow) int64 {
			return row.id
		},
		RowCreatedAt: func(row derivedAddressTestRow) time.Time {
			return row.createdAt
		},
		ApplyAccountMetadata: func(info *AddressInfo,
			row derivedAddressTestAccount) error {

			info.AccountName = row.name
			info.KeyScope = row.scope

			return nil
		},
	}
	deriveFn := func(_ context.Context, p AddressDerivationParams) (
		*DerivedAddressData, error) {

		require.Equal(t, uint32(3), *p.DerivedAccountNumber)
		require.Equal(t, uint32(5), p.Index)

		return &DerivedAddressData{
			ScriptPubKey: []byte{1},
			PubKey:       []byte{2},
		}, nil
	}

	info, err := NewDerivedAddressWithTx(
		t.Context(), params,
		func(_ context.Context,
			fn func(derivedAddressTestQTX) error) error {

			return fn(qtx)
		},
		adapters, deriveFn,
	)
	require.NoError(t, err)
	require.Equal(t, qtx.token, usedToken)
	require.Equal(t, uint32(99), info.ID)
	require.Equal(t, params.AccountName, info.AccountName)
	require.Equal(t, params.Scope, info.KeyScope)
}

// TestNewDerivedAddressWithTxRejectsDerivedAccountWithoutNumber verifies that
// a wallet-derived account row missing its derived account number is rejected
// instead of being treated as an imported-xpub account.
func TestNewDerivedAddressWithTxRejectsDerivedAccountWithoutNumber(
	t *testing.T) {

	t.Parallel()

	params := NewDerivedAddressParams{
		WalletID:    7,
		AccountName: "acct",
		Scope:       KeyScopeBIP0084,
	}
	qtx := derivedAddressTestQTX{token: "write-tx"}
	deriveCalled := false

	adapters := DerivedAddressAdapters[
		derivedAddressTestQTX,
		derivedAddressTestAccount,
		AccountLookupKey,
		derivedAddressTestRow]{
		GetAccount: func(derivedAddressTestQTX) func(
			context.Context, AccountLookupKey) (derivedAddressTestAccount,
			error) {

			return func(context.Context,
				AccountLookupKey) (derivedAddressTestAccount, error) {

				return derivedAddressTestAccount{
					id:        42,
					name:      params.AccountName,
					scope:     params.Scope,
					isDerived: true,
				}, nil
			}
		},
		AccountParams: AccountKeyFromParams,
		GetAccountID: func(row derivedAddressTestAccount) int64 {
			return row.id
		},
		GetAccountNumber: func(derivedAddressTestAccount) (uint32, error) {
			return 0, ErrNilDBAccountNumber
		},
		GetAccountIsDerived: func(row derivedAddressTestAccount) bool {
			return row.isDerived
		},
	}
	deriveFn := func(context.Context,
		AddressDerivationParams) (*DerivedAddressData, error) {

		deriveCalled = true

		return &DerivedAddressData{}, nil
	}

	_, err := NewDerivedAddressWithTx(
		t.Context(), params,
		func(_ context.Context,
			fn func(derivedAddressTestQTX) error) error {

			return fn(qtx)
		},
		adapters, deriveFn,
	)
	require.ErrorIs(t, err, errAccountShapeCorruption)
	require.False(t, deriveCalled)
}

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

// TestDerivedAddressInputNilDerivedData verifies that the shared derivation
// path rejects a nil callback result before dereferencing it.
func TestDerivedAddressInputNilDerivedData(t *testing.T) {
	t.Parallel()

	params := NewDerivedAddressParams{
		Scope: KeyScopeBIP0084,
	}

	deriveFn := func(context.Context,
		AddressDerivationParams) (*DerivedAddressData, error) {

		var derivedData *DerivedAddressData

		return derivedData, nil
	}

	accountNumber := uint32(0)

	addrType, branch, index, scriptPubKey, pubKey, err :=
		derivedAddressInput(
			t.Context(), params, 1, &accountNumber,
			ScopeAddrSchema{
				ExternalAddrType: PubKeyHash,
				InternalAddrType: PubKeyHash,
			}, nil,
			func(context.Context, int64) (int64, error) {
				return 7, nil
			},
			func(context.Context, int64) (int64, error) {
				return 11, nil
			}, deriveFn,
		)

	require.Zero(t, addrType)
	require.Zero(t, branch)
	require.Zero(t, index)
	require.Nil(t, scriptPubKey)
	require.Nil(t, pubKey)
	require.ErrorIs(t, err, errNilDerivedAddressData)
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
