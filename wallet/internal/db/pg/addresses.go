package pg

import (
	"context"
	"database/sql"
	"fmt"
	"iter"
	"time"

	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

var _ db.AddressStore = (*PostgresStore)(nil)

// GetAddress retrieves information about a specific address, identified by
// its script pubkey.
func (s *PostgresStore) GetAddress(ctx context.Context,
	query db.GetAddressQuery) (*db.AddressInfo, error) {

	getByScript := func(ctx context.Context, q db.GetAddressQuery) (*db.AddressInfo,
		error) {

		return db.GetAddress(
			ctx, s.queries.GetAddressByScriptPubKey,
			sqlcpg.GetAddressByScriptPubKeyParams{
				ScriptPubKey: q.ScriptPubKey,
				WalletID:     int64(q.WalletID),
			}, addressRowToInfo,
		)
	}

	return db.GetAddressByQuery(ctx, query, getByScript)
}

// ListAddresses returns a page of addresses matching the given query.
func (s *PostgresStore) ListAddresses(ctx context.Context,
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
func (s *PostgresStore) IterAddresses(ctx context.Context,
	query db.ListAddressesQuery) iter.Seq2[db.AddressInfo, error] {

	return page.Iter(
		ctx, query, s.ListAddresses, db.NextListAddressesQuery,
	)
}

// GetAddressSecret retrieves the encrypted secret information for an address.
func (s *PostgresStore) GetAddressSecret(ctx context.Context,
	addressID uint32) (*db.AddressSecret, error) {

	return db.GetAddressSecret(
		ctx, s.queries.GetAddressSecret, addressID, addressSecretRowToSecret,
	)
}

// NewDerivedAddress creates a new address for a given account and key
// scope.
func (s *PostgresStore) NewDerivedAddress(ctx context.Context,
	params db.NewDerivedAddressParams,
	deriveFn db.AddressDerivationFunc) (*db.AddressInfo, error) {

	adapters := db.DerivedAddressAdapters[
		*sqlcpg.Queries,
		sqlcpg.GetAccountByWalletScopeAndNameRow,
		db.AccountLookupKey,
		sqlcpg.CreateDerivedAddressRow]{
		GetAccount:    getAccountFromKey(s.queries),
		AccountParams: db.AccountKeyFromParams,
		GetAccountID:  derivedAddressGetAccountID,
		GetExtIndex:   derivedAddressGetExtIndex,
		GetIntIndex:   derivedAddressGetIntIndex,
		CreateAddr:    derivedAddressCreateAddr,
		RowID:         derivedAddressRowID,
		RowCreatedAt:  derivedAddressRowCreatedAt,
	}

	return db.NewDerivedAddressWithTx(ctx, params, s.ExecuteTx, adapters, deriveFn)
}

// NewImportedAddress imports a new address, script, or private key.
func (s *PostgresStore) NewImportedAddress(ctx context.Context,
	params db.NewImportedAddressParams) (*db.AddressInfo, error) {

	adapters := db.ImportedAddressAdapters[
		*sqlcpg.Queries,
		sqlcpg.GetAccountByWalletScopeAndNameRow,
		db.AccountLookupKey,
		sqlcpg.CreateImportedAddressParams,
		sqlcpg.CreateImportedAddressRow,
		sqlcpg.InsertAddressSecretParams]{
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
func getAccountFromKey(qtx *sqlcpg.Queries) func(context.Context,
	db.AccountLookupKey) (sqlcpg.GetAccountByWalletScopeAndNameRow, error) {

	return func(ctx context.Context,
		key db.AccountLookupKey) (sqlcpg.GetAccountByWalletScopeAndNameRow,
		error) {

		return qtx.GetAccountByWalletScopeAndName(
			ctx, sqlcpg.GetAccountByWalletScopeAndNameParams{
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
	row sqlcpg.GetAccountByWalletScopeAndNameRow) int64 {

	return row.ID
}

// derivedAddressGetExtIndex returns the external index query.
func derivedAddressGetExtIndex(qtx *sqlcpg.Queries) func(context.Context,
	int64) (int64, error) {

	return qtx.GetAndIncrementNextExternalIndex
}

// derivedAddressGetIntIndex returns the internal index query.
func derivedAddressGetIntIndex(qtx *sqlcpg.Queries) func(context.Context,
	int64) (int64, error) {

	return qtx.GetAndIncrementNextInternalIndex
}

// derivedAddressCreateAddr returns the derived address insert helper.
func derivedAddressCreateAddr(qtx *sqlcpg.Queries) func(context.Context,
	int64, db.AddressType, uint32, uint32, []byte) (sqlcpg.CreateDerivedAddressRow,
	error) {

	return func(ctx context.Context, accountID int64, addrType db.AddressType,
		branch uint32, index uint32,
		scriptPubKey []byte) (sqlcpg.CreateDerivedAddressRow, error) {

		branchNum, err := db.Uint32ToInt16(branch)
		if err != nil {
			return sqlcpg.CreateDerivedAddressRow{}, fmt.Errorf(
				"address branch: %w", err,
			)
		}

		return qtx.CreateDerivedAddress(
			ctx, sqlcpg.CreateDerivedAddressParams{
				AccountID:    accountID,
				ScriptPubKey: scriptPubKey,
				TypeID:       int16(addrType),
				AddressBranch: sql.NullInt16{
					Int16: branchNum,
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
func derivedAddressRowID(row sqlcpg.CreateDerivedAddressRow) int64 {
	return row.ID
}

// derivedAddressRowCreatedAt returns the CreatedAt timestamp.
func derivedAddressRowCreatedAt(
	row sqlcpg.CreateDerivedAddressRow) time.Time {

	return row.CreatedAt
}

// importedAddressGetAccountID extracts the account ID from a row.
func importedAddressGetAccountID(
	row sqlcpg.GetAccountByWalletScopeAndNameRow) int64 {

	return row.ID
}

// createImportedAddress returns the imported address insert helper.
func createImportedAddress(qtx *sqlcpg.Queries) func(context.Context,
	sqlcpg.CreateImportedAddressParams) (sqlcpg.CreateImportedAddressRow,
	error) {

	return qtx.CreateImportedAddress
}

// insertAddressSecret returns the secret insert helper.
func insertAddressSecret(qtx *sqlcpg.Queries) func(context.Context,
	sqlcpg.InsertAddressSecretParams) error {

	return qtx.InsertAddressSecret
}

// createImportedAddressParams maps imported params to sqlc params.
func createImportedAddressParams(accountID int64,
	params db.NewImportedAddressParams) sqlcpg.CreateImportedAddressParams {

	return sqlcpg.CreateImportedAddressParams{
		AccountID:    accountID,
		ScriptPubKey: params.ScriptPubKey,
		TypeID:       int16(params.AddressType),
		PubKey:       params.PubKey,
	}
}

// insertAddressSecretParams maps imported params to secret params.
func insertAddressSecretParams(addressID int64,
	params db.NewImportedAddressParams) sqlcpg.InsertAddressSecretParams {

	return sqlcpg.InsertAddressSecretParams{
		AddressID:        addressID,
		EncryptedPrivKey: params.EncryptedPrivateKey,
		EncryptedScript:  params.EncryptedScript,
	}
}

// importedAddressRowID returns the created address ID.
func importedAddressRowID(row sqlcpg.CreateImportedAddressRow) int64 {
	return row.ID
}

// importedAddressRowCreatedAt returns the CreatedAt timestamp.
func importedAddressRowCreatedAt(
	row sqlcpg.CreateImportedAddressRow) time.Time {

	return row.CreatedAt
}

// addressSecretRowToSecret converts a PostgreSQL address secret row to an
// AddressSecret struct.
func addressSecretRowToSecret(
	row sqlcpg.GetAddressSecretRow) (*db.AddressSecret, error) {

	return db.AddressSecretRowToSecret(db.AddressSecretRow{
		AddressID:        row.AddressID,
		EncryptedPrivKey: row.EncryptedPrivKey,
		EncryptedScript:  row.EncryptedScript,
	})
}

// addressInfoRow is a type constraint that unifies all PostgreSQL address
// row types that share the same field structure. This enables a single
// generic conversion function to handle all address query result types.
type addressInfoRow interface {
	sqlcpg.GetAddressByScriptPubKeyRow |
		sqlcpg.ListAddressesByAccountRow
}

// addressRowToInfo converts a PostgreSQL address row to an AddressInfo
// struct.
func addressRowToInfo[T addressInfoRow](row T) (*db.AddressInfo, error) {
	// Direct conversion works only because all constraint types have
	// identical fields. If sqlc types diverge, compilation will fail.
	base := sqlcpg.GetAddressByScriptPubKeyRow(row)

	info, err := db.AddressRowToInfo(db.AddressInfoRow[int16, int16]{
		ID:            base.ID,
		AccountID:     base.AccountID,
		TypeID:        base.TypeID,
		OriginID:      base.OriginID,
		HasPrivateKey: base.HasPrivateKey,
		HasScript:     base.HasScript,
		CreatedAt:     base.CreatedAt,
		AddressBranch: sql.NullInt64{
			Int64: int64(base.AddressBranch.Int16),
			Valid: base.AddressBranch.Valid,
		},
		AddressIndex: base.AddressIndex,
		ScriptPubKey: base.ScriptPubKey,
		PubKey:       base.PubKey,
		IDToAddrType: db.IDToAddressType[int16],
		IDToOrigin:   db.IDToOrigin[int16],
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// listAddressesByAccount lists addresses filtered by wallet ID, key scope,
// and account name, with pagination support.
func listAddressesByAccount(ctx context.Context, q *sqlcpg.Queries,
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
	q db.ListAddressesQuery) sqlcpg.ListAddressesByAccountParams {

	params := sqlcpg.ListAddressesByAccountParams{
		WalletID:    int64(q.WalletID),
		Purpose:     int64(q.Scope.Purpose),
		CoinType:    int64(q.Scope.Coin),
		AccountName: q.AccountName,
		PageLimit:   int64(q.Page.QueryLimit()),
	}

	if cursor, ok := q.Page.After(); ok {
		params.CursorID = sql.NullInt64{
			Int64: int64(cursor),
			Valid: true,
		}
	}

	return params
}
