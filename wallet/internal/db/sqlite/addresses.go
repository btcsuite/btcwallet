package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"iter"
	"time"

	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

var _ db.AddressStore = (*SqliteStore)(nil)

// GetAddress retrieves information about a specific address, identified by
// its script pubkey.
func (s *SqliteStore) GetAddress(ctx context.Context,
	query db.GetAddressQuery) (*db.AddressInfo, error) {

	getByScript := func(ctx context.Context,
		q db.GetAddressQuery) (*db.AddressInfo, error) {

		return db.GetAddress(
			ctx, s.queries.GetAddressByScriptPubKey,
			sqlcsqlite.GetAddressByScriptPubKeyParams{
				WalletID:     int64(q.WalletID),
				ScriptPubKey: q.ScriptPubKey,
			}, addressRowToInfo,
		)
	}

	return db.GetAddressByQuery(ctx, query, getByScript)
}

// ListAddresses returns a page of addresses matching the given query.
func (s *SqliteStore) ListAddresses(ctx context.Context,
	query db.ListAddressesQuery) (page.Result[db.AddressInfo, uint32], error) {

	items, err := listAddressesByAccount(ctx, s.queries, query)
	if err != nil {
		return page.Result[db.AddressInfo, uint32]{}, err
	}

	result := page.BuildResult(
		query.Page, items,
		func(item db.AddressInfo) uint32 {
			return item.ID
		},
	)

	return result, nil
}

// IterAddresses returns an iterator over paginated address results.
func (s *SqliteStore) IterAddresses(ctx context.Context,
	query db.ListAddressesQuery) iter.Seq2[db.AddressInfo, error] {

	return page.Iter(
		ctx, query, s.ListAddresses, db.NextListAddressesQuery,
	)
}

// GetAddressSecret retrieves the encrypted secret information for an address.
func (s *SqliteStore) GetAddressSecret(ctx context.Context,
	addressID uint32) (*db.AddressSecret, error) {

	return db.GetAddressSecret(
		ctx, s.queries.GetAddressSecret, addressID,
		addressSecretRowToSecret,
	)
}

// NewDerivedAddress creates a new address for a given account and key
// scope.
func (s *SqliteStore) NewDerivedAddress(ctx context.Context,
	params db.NewDerivedAddressParams,
	deriveFn db.AddressDerivationFunc) (*db.AddressInfo, error) {

	adapters := db.DerivedAddressAdapters[
		*sqlcsqlite.Queries,
		sqlcsqlite.GetAccountByWalletScopeAndNameRow,
		db.AccountLookupKey,
		sqlcsqlite.CreateDerivedAddressRow]{
		GetAccount:    getAccountFromKey(s.queries),
		AccountParams: db.AccountKeyFromParams,
		GetAccountID:  derivedAddressGetAccountID,
		GetExtIndex:   derivedAddressGetExtIndex,
		GetIntIndex:   derivedAddressGetIntIndex,
		CreateAddr:    derivedAddressCreateAddr,
		RowID:         derivedAddressRowID,
		RowCreatedAt:  derivedAddressRowCreatedAt,
	}

	return db.NewDerivedAddressWithTx(
		ctx, params, s.ExecuteTx, adapters, deriveFn,
	)
}

// NewImportedAddress imports a new address, script, or private key.
func (s *SqliteStore) NewImportedAddress(ctx context.Context,
	params db.NewImportedAddressParams) (*db.AddressInfo, error) {

	adapters := db.ImportedAddressAdapters[
		*sqlcsqlite.Queries,
		sqlcsqlite.GetAccountByWalletScopeAndNameRow,
		db.AccountLookupKey,
		sqlcsqlite.CreateImportedAddressParams,
		sqlcsqlite.CreateImportedAddressRow,
		sqlcsqlite.InsertAddressSecretParams]{
		GetAccount:    getAccountFromKey(s.queries),
		AccountParams: db.AccountKeyFromImportedParams,
		GetAccountID:  importedAddressGetAccountID,
		CreateAddr:    createImportedAddress,
		CreateParams:  createImportedAddressParams,
		InsertSecret:  insertAddressSecret,
		SecretParams:  insertAddressSecretParams,
		RowID:         importedAddressRowID,
		RowCreatedAt:  importedAddressRowCreatedAt,
	}

	return db.NewImportedAddressWithTx(ctx, params, s.ExecuteTx, adapters)
}

// getAccountFromKey returns a helper to look up accounts by key.
func getAccountFromKey(qtx *sqlcsqlite.Queries) func(context.Context,
	db.AccountLookupKey) (sqlcsqlite.GetAccountByWalletScopeAndNameRow, error) {

	return func(ctx context.Context,
		key db.AccountLookupKey) (sqlcsqlite.GetAccountByWalletScopeAndNameRow,
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

// derivedAddressGetAccountID extracts the account ID from a row.
func derivedAddressGetAccountID(
	row sqlcsqlite.GetAccountByWalletScopeAndNameRow) int64 {

	return row.ID
}

// derivedAddressGetExtIndex returns the external index query.
func derivedAddressGetExtIndex(
	qtx *sqlcsqlite.Queries) func(context.Context, int64) (int64, error) {

	return qtx.GetAndIncrementNextExternalIndex
}

// derivedAddressGetIntIndex returns the internal index query.
func derivedAddressGetIntIndex(
	qtx *sqlcsqlite.Queries) func(context.Context, int64) (int64, error) {

	return qtx.GetAndIncrementNextInternalIndex
}

// derivedAddressCreateAddr returns the derived address insert helper.
func derivedAddressCreateAddr(
	qtx *sqlcsqlite.Queries,
) func(context.Context, int64, db.AddressType, uint32, uint32, []byte) (
	sqlcsqlite.CreateDerivedAddressRow, error,
) {

	return func(ctx context.Context, accountID int64, addrType db.AddressType,
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

// derivedAddressRowID returns the created address ID.
func derivedAddressRowID(
	row sqlcsqlite.CreateDerivedAddressRow) int64 {

	return row.ID
}

// derivedAddressRowCreatedAt returns the CreatedAt timestamp.
func derivedAddressRowCreatedAt(
	row sqlcsqlite.CreateDerivedAddressRow) time.Time {

	return row.CreatedAt
}

// importedAddressGetAccountID extracts the account ID from a row.
func importedAddressGetAccountID(
	row sqlcsqlite.GetAccountByWalletScopeAndNameRow) int64 {

	return row.ID
}

// createImportedAddress returns the imported address insert helper.
func createImportedAddress(qtx *sqlcsqlite.Queries) func(context.Context,
	sqlcsqlite.CreateImportedAddressParams) (
	sqlcsqlite.CreateImportedAddressRow, error) {

	return qtx.CreateImportedAddress
}

// insertAddressSecret returns the secret insert helper.
func insertAddressSecret(qtx *sqlcsqlite.Queries) func(context.Context,
	sqlcsqlite.InsertAddressSecretParams) error {

	return qtx.InsertAddressSecret
}

// createImportedAddressParams maps imported params to sqlc params.
func createImportedAddressParams(accountID int64,
	params db.NewImportedAddressParams) sqlcsqlite.CreateImportedAddressParams {

	return sqlcsqlite.CreateImportedAddressParams{
		AccountID:    accountID,
		ScriptPubKey: params.ScriptPubKey,
		TypeID:       int64(params.AddressType),
		PubKey:       params.PubKey,
	}
}

// importedAddressRowID returns the created address ID.
func importedAddressRowID(row sqlcsqlite.CreateImportedAddressRow) int64 {
	return row.ID
}

// importedAddressRowCreatedAt returns the CreatedAt timestamp.
func importedAddressRowCreatedAt(
	row sqlcsqlite.CreateImportedAddressRow) time.Time {

	return row.CreatedAt
}

// insertAddressSecretParams maps imported params to secret params.
func insertAddressSecretParams(addressID int64,
	params db.NewImportedAddressParams) sqlcsqlite.InsertAddressSecretParams {

	return sqlcsqlite.InsertAddressSecretParams{
		AddressID:        addressID,
		EncryptedPrivKey: params.EncryptedPrivateKey,
		EncryptedScript:  params.EncryptedScript,
	}
}

// addressSecretRowToSecret converts a SQLite address secret row to an
// AddressSecret struct.
func addressSecretRowToSecret(
	row sqlcsqlite.GetAddressSecretRow) (*db.AddressSecret, error) {

	return db.AddressSecretRowToSecret(db.AddressSecretRow{
		AddressID:        row.AddressID,
		EncryptedPrivKey: row.EncryptedPrivKey,
		EncryptedScript:  row.EncryptedScript,
	})
}

// addressInfoRow is a type constraint union that represents all SQLite
// address row types that share the same field structure. This enables a
// single generic conversion function to handle all address query result types.
type addressInfoRow interface {
	sqlcsqlite.GetAddressByScriptPubKeyRow |
		sqlcsqlite.ListAddressesByAccountRow
}

// addressRowToInfo converts a SQLite address row to an AddressInfo
// struct.
func addressRowToInfo[T addressInfoRow](row T) (*db.AddressInfo,
	error) {
	// Direct conversion works only because all constraint types have
	// identical fields. If sqlc types diverge, compilation will fail.
	base := sqlcsqlite.GetAddressByScriptPubKeyRow(row)

	info, err := db.AddressRowToInfo(db.AddressInfoRow[int64, int64]{
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
		IDToAddrType:  db.IDToAddressType[int64],
		IDToOrigin:    db.IDToOrigin[int64],
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// listAddressesByAccount lists addresses filtered by wallet ID, key
// scope, and account name, with pagination support.
func listAddressesByAccount(ctx context.Context, q *sqlcsqlite.Queries,
	query db.ListAddressesQuery) ([]db.AddressInfo, error) {

	rows, err := q.ListAddressesByAccount(
		ctx, buildAddressPageParams(query),
	)
	if err != nil {
		return nil, fmt.Errorf("list addresses by account: %w", err)
	}

	items := make([]db.AddressInfo, len(rows))
	for i, row := range rows {
		item, err := addressRowToInfo(row)
		if err != nil {
			return nil,
				fmt.Errorf("list addresses by account: map address row: %w",
					err)
		}

		items[i] = *item
	}

	return items, nil
}

// buildAddressPageParams translates a ListAddresses query to
// ListAddressesByAccount parameters, handling pagination cursors.
func buildAddressPageParams(
	q db.ListAddressesQuery) sqlcsqlite.ListAddressesByAccountParams {

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
