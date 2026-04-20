package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"iter"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

var _ db.AddressStore = (*Store)(nil)

// GetAddress retrieves information about a specific address, identified by
// its script pubkey.
func (s *Store) GetAddress(ctx context.Context,
	query db.GetAddressQuery) (*db.AddressInfo, error) {

	getByScript := func(ctx context.Context,
		q db.GetAddressQuery) (*db.AddressInfo, error) {

		return db.GetAddress(
			ctx, s.queries.GetAddressByScriptPubKey,
			sqlc.GetAddressByScriptPubKeyParams{
				WalletID:     int64(q.WalletID),
				ScriptPubKey: q.ScriptPubKey,
			}, addressRowToInfo,
		)
	}

	return db.GetAddressByQuery(ctx, query, getByScript)
}

// ListAddresses returns a page of addresses matching the given query.
func (s *Store) ListAddresses(ctx context.Context,
	query db.ListAddressesQuery) (page.Result[db.AddressInfo, uint32], error) {

	if query.Page.Limit() == 0 {
		return page.Result[db.AddressInfo, uint32]{}, db.ErrInvalidPageLimit
	}

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
func (s *Store) IterAddresses(ctx context.Context,
	query db.ListAddressesQuery) iter.Seq2[db.AddressInfo, error] {

	return page.Iter(
		ctx, query, s.ListAddresses, db.NextListAddressesQuery,
	)
}

// GetAddressSecret retrieves the encrypted secret information for an address.
func (s *Store) GetAddressSecret(ctx context.Context,
	addressID uint32) (*db.AddressSecret, error) {

	return db.GetAddressSecret(
		ctx, s.queries.GetAddressSecret, addressID,
		addressSecretRowToSecret,
	)
}

// NewDerivedAddress creates a new address for a given account and key
// scope.
func (s *Store) NewDerivedAddress(ctx context.Context,
	params db.NewDerivedAddressParams,
	deriveFn db.AddressDerivationFunc) (*db.AddressInfo, error) {

	adapters := db.DerivedAddressAdapters[
		*sqlc.Queries,
		sqlc.GetAccountByWalletScopeAndNameRow,
		db.AccountLookupKey,
		sqlc.CreateDerivedAddressRow]{
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
		ctx, params, s.execWrite, adapters, deriveFn,
	)
}

// NewImportedAddress imports a new address, script, or private key.
func (s *Store) NewImportedAddress(ctx context.Context,
	params db.NewImportedAddressParams) (*db.AddressInfo, error) {

	adapters := db.ImportedAddressAdapters[
		*sqlc.Queries,
		sqlc.GetAccountByWalletScopeAndNameRow,
		db.AccountLookupKey,
		sqlc.CreateImportedAddressParams,
		sqlc.CreateImportedAddressRow,
		sqlc.InsertAddressSecretParams]{
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

	return db.NewImportedAddressWithTx(ctx, params, s.execWrite, adapters)
}

// getAccountFromKey returns a helper to look up accounts by key.
func getAccountFromKey(qtx *sqlc.Queries) func(context.Context,
	db.AccountLookupKey) (sqlc.GetAccountByWalletScopeAndNameRow, error) {

	return func(ctx context.Context,
		key db.AccountLookupKey) (sqlc.GetAccountByWalletScopeAndNameRow,
		error) {

		return qtx.GetAccountByWalletScopeAndName(
			ctx, sqlc.GetAccountByWalletScopeAndNameParams{
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
	row sqlc.GetAccountByWalletScopeAndNameRow) int64 {

	return row.ID
}

// derivedAddressGetExtIndex returns the external index query.
func derivedAddressGetExtIndex(
	qtx *sqlc.Queries) func(context.Context, int64) (int64, error) {

	return qtx.GetAndIncrementNextExternalIndex
}

// derivedAddressGetIntIndex returns the internal index query.
func derivedAddressGetIntIndex(
	qtx *sqlc.Queries) func(context.Context, int64) (int64, error) {

	return qtx.GetAndIncrementNextInternalIndex
}

// derivedAddressCreateAddr returns the derived address insert helper.
func derivedAddressCreateAddr(
	qtx *sqlc.Queries,
) func(context.Context, int64, db.AddressType, uint32, uint32, []byte) (
	sqlc.CreateDerivedAddressRow, error,
) {

	return func(ctx context.Context, accountID int64, addrType db.AddressType,
		branch uint32, index uint32,
		scriptPubKey []byte) (sqlc.CreateDerivedAddressRow, error) {

		return qtx.CreateDerivedAddress(
			ctx, sqlc.CreateDerivedAddressParams{
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
	row sqlc.CreateDerivedAddressRow) int64 {

	return row.ID
}

// derivedAddressRowCreatedAt returns the CreatedAt timestamp.
func derivedAddressRowCreatedAt(
	row sqlc.CreateDerivedAddressRow) time.Time {

	return row.CreatedAt
}

// importedAddressGetAccountID extracts the account ID from a row.
func importedAddressGetAccountID(
	row sqlc.GetAccountByWalletScopeAndNameRow) int64 {

	return row.ID
}

// createImportedAddress returns the imported address insert helper.
func createImportedAddress(qtx *sqlc.Queries) func(context.Context,
	sqlc.CreateImportedAddressParams) (
	sqlc.CreateImportedAddressRow, error) {

	return qtx.CreateImportedAddress
}

// insertAddressSecret returns the secret insert helper.
func insertAddressSecret(qtx *sqlc.Queries) func(context.Context,
	sqlc.InsertAddressSecretParams) error {

	return qtx.InsertAddressSecret
}

// createImportedAddressParams maps imported params to sqlc params.
func createImportedAddressParams(accountID int64,
	params db.NewImportedAddressParams) sqlc.CreateImportedAddressParams {

	return sqlc.CreateImportedAddressParams{
		AccountID:    accountID,
		ScriptPubKey: params.ScriptPubKey,
		TypeID:       int64(params.AddressType),
		PubKey:       params.PubKey,
	}
}

// importedAddressRowID returns the created address ID.
func importedAddressRowID(row sqlc.CreateImportedAddressRow) int64 {
	return row.ID
}

// importedAddressRowCreatedAt returns the CreatedAt timestamp.
func importedAddressRowCreatedAt(
	row sqlc.CreateImportedAddressRow) time.Time {

	return row.CreatedAt
}

// insertAddressSecretParams maps imported params to secret params.
func insertAddressSecretParams(addressID int64,
	params db.NewImportedAddressParams) sqlc.InsertAddressSecretParams {

	return sqlc.InsertAddressSecretParams{
		AddressID:        addressID,
		EncryptedPrivKey: params.EncryptedPrivateKey,
		EncryptedScript:  params.EncryptedScript,
	}
}

// addressSecretRowToSecret converts a SQLite address secret row to an
// AddressSecret struct.
func addressSecretRowToSecret(
	row sqlc.GetAddressSecretRow) (*db.AddressSecret, error) {

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
	sqlc.GetAddressByScriptPubKeyRow |
		sqlc.ListAddressesByAccountRow
}

// addressRowToInfo converts a SQLite address row to an AddressInfo
// struct.
func addressRowToInfo[T addressInfoRow](row T) (*db.AddressInfo,
	error) {
	// Direct conversion works only because all constraint types have
	// identical fields. If sqlc types diverge, compilation will fail.
	base := sqlc.GetAddressByScriptPubKeyRow(row)

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
func listAddressesByAccount(ctx context.Context, q *sqlc.Queries,
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
	q db.ListAddressesQuery) sqlc.ListAddressesByAccountParams {

	params := sqlc.ListAddressesByAccountParams{
		WalletID:    int64(q.WalletID),
		Purpose:     int64(q.Scope.Purpose),
		CoinType:    int64(q.Scope.Coin),
		AccountName: q.AccountName,
		PageLimit:   int64(q.Page.Limit()) + 1,
	}

	if q.Page.After != nil {
		params.CursorID = int64(*q.Page.After)
	}

	return params
}
