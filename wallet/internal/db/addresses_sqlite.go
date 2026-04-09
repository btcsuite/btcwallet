package db

import (
	"context"
	"database/sql"
	"fmt"
	"iter"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

var _ AddressStore = (*SqliteStore)(nil)

// GetAddress retrieves information about a specific address, identified by
// its script pubkey.
func (s *SqliteStore) GetAddress(ctx context.Context,
	query GetAddressQuery) (*AddressInfo, error) {

	getByScript := func(ctx context.Context, q GetAddressQuery) (*AddressInfo,
		error) {

		return GetAddress(
			ctx, s.queries.GetAddressByScriptPubKey,
			sqlcsqlite.GetAddressByScriptPubKeyParams{
				WalletID:     int64(q.WalletID),
				ScriptPubKey: q.ScriptPubKey,
			}, sqliteAddressRowToInfo,
		)
	}

	return GetAddressByQuery(ctx, query, getByScript)
}

// ListAddresses returns a page of addresses matching the given query.
func (s *SqliteStore) ListAddresses(ctx context.Context,
	query ListAddressesQuery) (page.Result[AddressInfo, uint32], error) {

	items, err := sqliteListAddressesByAccount(ctx, s.queries, query)
	if err != nil {
		return page.Result[AddressInfo, uint32]{}, err
	}

	result := page.BuildResult(
		query.Page, items,
		func(item AddressInfo) uint32 {
			return item.ID
		},
	)

	return result, nil
}

// IterAddresses returns an iterator over paginated address results.
func (s *SqliteStore) IterAddresses(ctx context.Context,
	query ListAddressesQuery) iter.Seq2[AddressInfo, error] {

	return page.Iter(
		ctx, query, s.ListAddresses, NextListAddressesQuery,
	)
}

// GetAddressSecret retrieves the encrypted secret information for an address.
func (s *SqliteStore) GetAddressSecret(ctx context.Context,
	addressID uint32) (*AddressSecret, error) {

	return GetAddressSecret(
		ctx, s.queries.GetAddressSecret, addressID,
		sqliteAddressSecretRowToSecret,
	)
}

// NewDerivedAddress creates a new address for a given account and key
// scope.
func (s *SqliteStore) NewDerivedAddress(ctx context.Context,
	params NewDerivedAddressParams,
	deriveFn AddressDerivationFunc) (*AddressInfo, error) {

	adapters := DerivedAddressAdapters[
		*sqlcsqlite.Queries,
		sqlcsqlite.GetAccountByWalletScopeAndNameRow,
		AccountLookupKey,
		sqlcsqlite.CreateDerivedAddressRow]{
		GetAccount:    sqliteGetAccountFromKey(s.queries),
		AccountParams: AccountKeyFromParams,
		GetAccountID:  newDerivedAddressGetAccountIDSQLite,
		GetExtIndex:   newDerivedAddressGetExtIndexSQLite,
		GetIntIndex:   newDerivedAddressGetIntIndexSQLite,
		CreateAddr:    newDerivedAddressCreateAddrSQLite,
		RowID:         newDerivedAddressRowIDSQLite,
		RowCreatedAt:  newDerivedAddressRowCreatedAtSQLite,
	}

	return NewDerivedAddressWithTx(ctx, params, s.ExecuteTx, adapters, deriveFn)
}

// NewImportedAddress imports a new address, script, or private key.
func (s *SqliteStore) NewImportedAddress(ctx context.Context,
	params NewImportedAddressParams) (*AddressInfo, error) {

	adapters := ImportedAddressAdapters[
		*sqlcsqlite.Queries,
		sqlcsqlite.GetAccountByWalletScopeAndNameRow,
		AccountLookupKey,
		sqlcsqlite.CreateImportedAddressParams,
		sqlcsqlite.CreateImportedAddressRow,
		sqlcsqlite.InsertAddressSecretParams]{
		GetAccount:    sqliteGetAccountFromKey(s.queries),
		AccountParams: AccountKeyFromImportedParams,
		GetAccountID:  newImportedAddressGetAccountIDSQLite,
		CreateAddr:    sqliteCreateImportedAddress,
		CreateParams:  createImportedAddressParamsSQLite,
		InsertSecret:  sqliteInsertAddressSecret,
		SecretParams:  insertAddressSecretParamsSQLite,
		RowID:         importedAddressRowIDSQLite,
		RowCreatedAt:  importedAddressRowCreatedAtSQLite,
	}

	return NewImportedAddressWithTx(ctx, params, s.ExecuteTx, adapters)
}

// sqliteGetAccountFromKey returns a helper to look up accounts by key.
func sqliteGetAccountFromKey(qtx *sqlcsqlite.Queries) func(context.Context,
	AccountLookupKey) (sqlcsqlite.GetAccountByWalletScopeAndNameRow, error) {

	return func(ctx context.Context,
		key AccountLookupKey) (sqlcsqlite.GetAccountByWalletScopeAndNameRow,
		error) {

		return qtx.GetAccountByWalletScopeAndName(
			ctx, sqlcsqlite.GetAccountByWalletScopeAndNameParams{
				WalletID:    key.WalletID,
				Purpose:     key.Purpose,
				CoinType:    key.CoinType,
				AccountName: key.AccountName,
			},
		)
	}
}

// newDerivedAddressGetAccountIDSQLite extracts the account ID from a row.
func newDerivedAddressGetAccountIDSQLite(
	row sqlcsqlite.GetAccountByWalletScopeAndNameRow) int64 {

	return row.ID
}

// newDerivedAddressGetExtIndexSQLite returns the external index query.
func newDerivedAddressGetExtIndexSQLite(
	qtx *sqlcsqlite.Queries) func(context.Context, int64) (int64, error) {

	return qtx.GetAndIncrementNextExternalIndex
}

// newDerivedAddressGetIntIndexSQLite returns the internal index query.
func newDerivedAddressGetIntIndexSQLite(
	qtx *sqlcsqlite.Queries) func(context.Context, int64) (int64, error) {

	return qtx.GetAndIncrementNextInternalIndex
}

// newDerivedAddressCreateAddrSQLite returns the derived address insert helper.
func newDerivedAddressCreateAddrSQLite(
	qtx *sqlcsqlite.Queries) func(context.Context, int64, AddressType, uint32,
	uint32, []byte) (sqlcsqlite.CreateDerivedAddressRow, error) {

	return func(ctx context.Context, accountID int64, addrType AddressType,
		branch uint32, index uint32,
		scriptPubKey []byte) (sqlcsqlite.CreateDerivedAddressRow, error) {

		return qtx.CreateDerivedAddress(
			ctx, sqlcsqlite.CreateDerivedAddressParams{
				AccountID:    accountID,
				ScriptPubKey: scriptPubKey,
				TypeID:       int64(addrType),
				AddressBranch: sql.NullInt64{
					Int64: int64(branch),
					Valid: true,
				},
				AddressIndex: sql.NullInt64{
					Int64: int64(index),
					Valid: true,
				},
				PubKey: nil,
			},
		)
	}
}

// newDerivedAddressRowIDSQLite returns the created address ID.
func newDerivedAddressRowIDSQLite(
	row sqlcsqlite.CreateDerivedAddressRow) int64 {

	return row.ID
}

// newDerivedAddressRowCreatedAtSQLite returns the CreatedAt timestamp.
func newDerivedAddressRowCreatedAtSQLite(
	row sqlcsqlite.CreateDerivedAddressRow) time.Time {

	return row.CreatedAt
}

// newImportedAddressGetAccountIDSQLite extracts the account ID from a row.
func newImportedAddressGetAccountIDSQLite(
	row sqlcsqlite.GetAccountByWalletScopeAndNameRow) int64 {

	return row.ID
}

// sqliteCreateImportedAddress returns the imported address insert helper.
func sqliteCreateImportedAddress(qtx *sqlcsqlite.Queries) func(context.Context,
	sqlcsqlite.CreateImportedAddressParams) (
	sqlcsqlite.CreateImportedAddressRow, error) {

	return qtx.CreateImportedAddress
}

// sqliteInsertAddressSecret returns the secret insert helper.
func sqliteInsertAddressSecret(qtx *sqlcsqlite.Queries) func(context.Context,
	sqlcsqlite.InsertAddressSecretParams) error {

	return qtx.InsertAddressSecret
}

// createImportedAddressParamsSQLite maps imported params to sqlc params.
func createImportedAddressParamsSQLite(accountID int64,
	params NewImportedAddressParams) sqlcsqlite.CreateImportedAddressParams {

	return sqlcsqlite.CreateImportedAddressParams{
		AccountID:    accountID,
		ScriptPubKey: params.ScriptPubKey,
		TypeID:       int64(params.AddressType),
		PubKey:       params.PubKey,
	}
}

// importedAddressRowIDSQLite returns the created address ID.
func importedAddressRowIDSQLite(row sqlcsqlite.CreateImportedAddressRow) int64 {
	return row.ID
}

// importedAddressRowCreatedAtSQLite returns the CreatedAt timestamp.
func importedAddressRowCreatedAtSQLite(
	row sqlcsqlite.CreateImportedAddressRow) time.Time {

	return row.CreatedAt
}

// insertAddressSecretParamsSQLite maps imported params to secret params.
func insertAddressSecretParamsSQLite(addressID int64,
	params NewImportedAddressParams) sqlcsqlite.InsertAddressSecretParams {

	return sqlcsqlite.InsertAddressSecretParams{
		AddressID:        addressID,
		EncryptedPrivKey: params.EncryptedPrivateKey,
		EncryptedScript:  params.EncryptedScript,
	}
}

// sqliteAddressSecretRowToSecret converts a SQLite address secret row to an
// AddressSecret struct.
func sqliteAddressSecretRowToSecret(
	row sqlcsqlite.GetAddressSecretRow) (*AddressSecret, error) {

	return AddressSecretRowToSecret(AddressSecretRow{
		AddressID:        row.AddressID,
		EncryptedPrivKey: row.EncryptedPrivKey,
		EncryptedScript:  row.EncryptedScript,
	})
}

// sqliteAddressInfoRow is a type constraint union that represents all SQLite
// address row types that share the same field structure. This enables a
// single generic conversion function to handle all address query result types.
type sqliteAddressInfoRow interface {
	sqlcsqlite.GetAddressByScriptPubKeyRow |
		sqlcsqlite.ListAddressesByAccountRow
}

// sqliteAddressRowToInfo converts a SQLite address row to an AddressInfo
// struct.
func sqliteAddressRowToInfo[T sqliteAddressInfoRow](row T) (*AddressInfo,
	error) {
	// Direct conversion works only because all constraint types have
	// identical fields. If sqlc types diverge, compilation will fail.
	base := sqlcsqlite.GetAddressByScriptPubKeyRow(row)

	info, err := addressRowToInfo(AddressInfoRow[int64, int64]{
		ID:            base.ID,
		AccountID:     base.AccountID,
		TypeID:        base.TypeID,
		OriginID:      base.OriginID,
		HasPrivateKey: base.HasPrivateKey,
		HasScript:     base.HasScript,
		CreatedAt:     base.CreatedAt,
		AddressBranch: base.AddressBranch,
		AddressIndex:  base.AddressIndex,
		ScriptPubKey:  base.ScriptPubKey,
		PubKey:        base.PubKey,
		IDToAddrType:  IDToAddressType[int64],
		IDToOrigin:    IDToOrigin[int64],
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// sqliteListAddressesByAccount lists addresses filtered by wallet ID, key
// scope, and account name, with pagination support.
func sqliteListAddressesByAccount(ctx context.Context, q *sqlcsqlite.Queries,
	query ListAddressesQuery) ([]AddressInfo, error) {

	rows, err := q.ListAddressesByAccount(
		ctx, sqliteBuildAddressPageParams(query),
	)
	if err != nil {
		return nil, fmt.Errorf("list addresses by account: %w", err)
	}

	items := make([]AddressInfo, len(rows))
	for i, row := range rows {
		item, err := sqliteAddressRowToInfo(row)
		if err != nil {
			return nil,
				fmt.Errorf("list addresses by account: map address row: %w",
					err)
		}

		items[i] = *item
	}

	return items, nil
}

// sqliteBuildAddressPageParams translates a ListAddresses query to
// ListAddressesByAccount parameters, handling pagination cursors.
func sqliteBuildAddressPageParams(
	q ListAddressesQuery) sqlcsqlite.ListAddressesByAccountParams {

	params := sqlcsqlite.ListAddressesByAccountParams{
		WalletID:    int64(q.WalletID),
		Purpose:     int64(q.Scope.Purpose),
		CoinType:    int64(q.Scope.Coin),
		AccountName: q.AccountName,
		PageLimit:   int64(q.Page.QueryLimit()),
	}

	if cursor, ok := q.Page.After(); ok {
		params.CursorID = int64(cursor)
	}

	return params
}
