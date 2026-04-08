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
			}, pgAddressRowToInfo,
		)
	}

	return db.GetAddressByQuery(ctx, query, getByScript)
}

// ListAddresses returns a page of addresses matching the given query.
func (s *PostgresStore) ListAddresses(ctx context.Context,
	query db.ListAddressesQuery) (page.Result[db.AddressInfo, uint32], error) {

	items, err := pgListAddressesByAccount(ctx, s.queries, query)
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
		ctx, s.queries.GetAddressSecret, addressID, pgAddressSecretRowToSecret,
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
		GetAccount:    pgGetAccountFromKey(s.queries),
		AccountParams: db.AccountKeyFromParams,
		GetAccountID:  newDerivedAddressGetAccountIDPg,
		GetExtIndex:   newDerivedAddressGetExtIndexPg,
		GetIntIndex:   newDerivedAddressGetIntIndexPg,
		CreateAddr:    newDerivedAddressCreateAddrPg,
		RowID:         newDerivedAddressRowIDPg,
		RowCreatedAt:  newDerivedAddressRowCreatedAtPg,
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
		GetAccount:    pgGetAccountFromKey(s.queries),
		AccountParams: db.AccountKeyFromImportedParams,
		GetAccountID:  newImportedAddressGetAccountIDPg,
		CreateAddr:    pgCreateImportedAddress,
		CreateParams:  createImportedAddressParamsPg,
		InsertSecret:  pgInsertAddressSecret,
		SecretParams:  insertAddressSecretParamsPg,
		RowID:         importedAddressRowIDPg,
		RowCreatedAt:  importedAddressRowCreatedAtPg,
	}

	return db.NewImportedAddressWithTx(ctx, params, s.ExecuteTx, adapters)
}

// pgGetAccountFromKey returns a helper to look up accounts by key.
func pgGetAccountFromKey(qtx *sqlcpg.Queries) func(context.Context,
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

// newDerivedAddressGetAccountIDPg extracts the account ID from a row.
func newDerivedAddressGetAccountIDPg(
	row sqlcpg.GetAccountByWalletScopeAndNameRow) int64 {

	return row.ID
}

// newDerivedAddressGetExtIndexPg returns the external index query.
func newDerivedAddressGetExtIndexPg(qtx *sqlcpg.Queries) func(context.Context,
	int64) (int64, error) {

	return qtx.GetAndIncrementNextExternalIndex
}

// newDerivedAddressGetIntIndexPg returns the internal index query.
func newDerivedAddressGetIntIndexPg(qtx *sqlcpg.Queries) func(context.Context,
	int64) (int64, error) {

	return qtx.GetAndIncrementNextInternalIndex
}

// newDerivedAddressCreateAddrPg returns the derived address insert helper.
func newDerivedAddressCreateAddrPg(qtx *sqlcpg.Queries) func(context.Context,
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

// newDerivedAddressRowIDPg returns the created address ID.
func newDerivedAddressRowIDPg(row sqlcpg.CreateDerivedAddressRow) int64 {
	return row.ID
}

// newDerivedAddressRowCreatedAtPg returns the CreatedAt timestamp.
func newDerivedAddressRowCreatedAtPg(
	row sqlcpg.CreateDerivedAddressRow) time.Time {

	return row.CreatedAt
}

// newImportedAddressGetAccountIDPg extracts the account ID from a row.
func newImportedAddressGetAccountIDPg(
	row sqlcpg.GetAccountByWalletScopeAndNameRow) int64 {

	return row.ID
}

// pgCreateImportedAddress returns the imported address insert helper.
func pgCreateImportedAddress(qtx *sqlcpg.Queries) func(context.Context,
	sqlcpg.CreateImportedAddressParams) (sqlcpg.CreateImportedAddressRow,
	error) {

	return qtx.CreateImportedAddress
}

// pgInsertAddressSecret returns the secret insert helper.
func pgInsertAddressSecret(qtx *sqlcpg.Queries) func(context.Context,
	sqlcpg.InsertAddressSecretParams) error {

	return qtx.InsertAddressSecret
}

// createImportedAddressParamsPg maps imported params to sqlc params.
func createImportedAddressParamsPg(accountID int64,
	params db.NewImportedAddressParams) sqlcpg.CreateImportedAddressParams {

	return sqlcpg.CreateImportedAddressParams{
		AccountID:    accountID,
		ScriptPubKey: params.ScriptPubKey,
		TypeID:       int16(params.AddressType),
		PubKey:       params.PubKey,
	}
}

// insertAddressSecretParamsPg maps imported params to secret params.
func insertAddressSecretParamsPg(addressID int64,
	params db.NewImportedAddressParams) sqlcpg.InsertAddressSecretParams {

	return sqlcpg.InsertAddressSecretParams{
		AddressID:        addressID,
		EncryptedPrivKey: params.EncryptedPrivateKey,
		EncryptedScript:  params.EncryptedScript,
	}
}

// importedAddressRowIDPg returns the created address ID.
func importedAddressRowIDPg(row sqlcpg.CreateImportedAddressRow) int64 {
	return row.ID
}

// importedAddressRowCreatedAtPg returns the CreatedAt timestamp.
func importedAddressRowCreatedAtPg(
	row sqlcpg.CreateImportedAddressRow) time.Time {

	return row.CreatedAt
}

// pgAddressSecretRowToSecret converts a PostgreSQL address secret row to an
// AddressSecret struct.
func pgAddressSecretRowToSecret(
	row sqlcpg.GetAddressSecretRow) (*db.AddressSecret, error) {

	return db.AddressSecretRowToSecret(db.AddressSecretRow{
		AddressID:        row.AddressID,
		EncryptedPrivKey: row.EncryptedPrivKey,
		EncryptedScript:  row.EncryptedScript,
	})
}

// pgAddressInfoRow is a type constraint that unifies all PostgreSQL address
// row types that share the same field structure. This enables a single
// generic conversion function to handle all address query result types.
type pgAddressInfoRow interface {
	sqlcpg.GetAddressByScriptPubKeyRow |
		sqlcpg.ListAddressesByAccountRow
}

// pgAddressRowToInfo converts a PostgreSQL address row to an AddressInfo
// struct.
func pgAddressRowToInfo[T pgAddressInfoRow](row T) (*db.AddressInfo, error) {
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

// pgListAddressesByAccount lists addresses filtered by wallet ID, key scope,
// and account name, with pagination support.
func pgListAddressesByAccount(ctx context.Context, q *sqlcpg.Queries,
	query db.ListAddressesQuery) ([]db.AddressInfo, error) {

	rows, err := q.ListAddressesByAccount(
		ctx, pgBuildAddressPageParams(query),
	)
	if err != nil {
		return nil, fmt.Errorf("list addresses by account: %w", err)
	}

	items := make([]db.AddressInfo, len(rows))
	for i, row := range rows {
		item, err := pgAddressRowToInfo(row)
		if err != nil {
			return nil,
				fmt.Errorf("list addresses by account: map address row: %w",
					err)
		}

		items[i] = *item
	}

	return items, nil
}

// pgBuildAddressPageParams translates a ListAddresses query to
// ListAddressesByAccount parameters, handling pagination cursors.
func pgBuildAddressPageParams(
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
