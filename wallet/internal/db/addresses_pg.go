package db

import (
	"context"
	"database/sql"
	"fmt"
	"iter"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

var _ AddressStore = (*PostgresStore)(nil)

// GetAddress retrieves information about a specific address, identified by
// its script pubkey.
func (s *PostgresStore) GetAddress(ctx context.Context,
	query GetAddressQuery) (*AddressInfo, error) {

	getByScript := func(ctx context.Context, q GetAddressQuery) (*AddressInfo,
		error) {

		return getAddress(
			ctx, s.queries.GetAddressByScriptPubKey,
			sqlcpg.GetAddressByScriptPubKeyParams{
				ScriptPubKey: q.ScriptPubKey,
				WalletID:     int64(q.WalletID),
			}, pgAddressRowToInfo,
		)
	}

	return getAddressByQuery(ctx, query, getByScript)
}

// ListAddresses returns a page of addresses matching the given query.
func (s *PostgresStore) ListAddresses(ctx context.Context,
	query ListAddressesQuery) (page.Result[AddressInfo, uint32], error) {

	items, err := pgListAddressesByAccount(ctx, s.queries, query)
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
func (s *PostgresStore) IterAddresses(ctx context.Context,
	query ListAddressesQuery) iter.Seq2[AddressInfo, error] {

	return page.Iter(
		ctx, query, s.ListAddresses, nextListAddressesQuery,
	)
}

// GetAddressSecret retrieves the encrypted secret information for an address.
func (s *PostgresStore) GetAddressSecret(ctx context.Context,
	addressID uint32) (*AddressSecret, error) {

	return getAddressSecret(
		ctx, s.queries.GetAddressSecret, addressID, pgAddressSecretRowToSecret,
	)
}

// NewDerivedAddress creates a new address for a given account and key
// scope.
func (s *PostgresStore) NewDerivedAddress(ctx context.Context,
	params NewDerivedAddressParams,
	deriveFn AddressDerivationFunc) (*AddressInfo, error) {

	adapters := derivedAddressAdapters[
		*sqlcpg.Queries,
		sqlcpg.GetAccountByWalletScopeAndNameRow,
		accountLookupKey,
		sqlcpg.CreateDerivedAddressRow]{
		getAccount:    pgGetAccountFromKey(s.queries),
		accountParams: accountKeyFromParams,
		getAccountID:  newDerivedAddressGetAccountIDPg,
		getExtIndex:   newDerivedAddressGetExtIndexPg,
		getIntIndex:   newDerivedAddressGetIntIndexPg,
		createAddr:    newDerivedAddressCreateAddrPg,
		rowID:         newDerivedAddressRowIDPg,
		rowCreatedAt:  newDerivedAddressRowCreatedAtPg,
	}

	return newDerivedAddressWithTx(ctx, params, s.ExecuteTx, adapters, deriveFn)
}

// NewImportedAddress imports a new address, script, or private key.
func (s *PostgresStore) NewImportedAddress(ctx context.Context,
	params NewImportedAddressParams) (*AddressInfo, error) {

	adapters := importedAddressAdapters[
		*sqlcpg.Queries,
		sqlcpg.GetAccountByWalletScopeAndNameRow,
		accountLookupKey,
		sqlcpg.CreateImportedAddressParams,
		sqlcpg.CreateImportedAddressRow,
		sqlcpg.InsertAddressSecretParams]{
		getAccount:    pgGetAccountFromKey(s.queries),
		accountParams: accountKeyFromImportedParams,
		getAccountID:  newImportedAddressGetAccountIDPg,
		createAddr:    pgCreateImportedAddress,
		createParams:  createImportedAddressParamsPg,
		insertSecret:  pgInsertAddressSecret,
		secretParams:  insertAddressSecretParamsPg,
		rowID:         importedAddressRowIDPg,
		rowCreatedAt:  importedAddressRowCreatedAtPg,
	}

	return newImportedAddressWithTx(ctx, params, s.ExecuteTx, adapters)
}

// pgGetAccountFromKey returns a helper to look up accounts by key.
func pgGetAccountFromKey(qtx *sqlcpg.Queries) func(context.Context,
	accountLookupKey) (sqlcpg.GetAccountByWalletScopeAndNameRow, error) {

	return func(ctx context.Context,
		key accountLookupKey) (sqlcpg.GetAccountByWalletScopeAndNameRow,
		error) {

		return qtx.GetAccountByWalletScopeAndName(
			ctx, sqlcpg.GetAccountByWalletScopeAndNameParams{
				WalletID:    key.walletID,
				Purpose:     key.purpose,
				CoinType:    key.coinType,
				AccountName: key.accountName,
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
	int64, AddressType, uint32, uint32, []byte) (sqlcpg.CreateDerivedAddressRow,
	error) {

	return func(ctx context.Context, accountID int64, addrType AddressType,
		branch uint32, index uint32,
		scriptPubKey []byte) (sqlcpg.CreateDerivedAddressRow, error) {

		branchNum, err := uint32ToInt16(branch)
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
	params NewImportedAddressParams) sqlcpg.CreateImportedAddressParams {

	return sqlcpg.CreateImportedAddressParams{
		AccountID:    accountID,
		ScriptPubKey: params.ScriptPubKey,
		TypeID:       int16(params.AddressType),
		PubKey:       params.PubKey,
	}
}

// insertAddressSecretParamsPg maps imported params to secret params.
func insertAddressSecretParamsPg(addressID int64,
	params NewImportedAddressParams) sqlcpg.InsertAddressSecretParams {

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
	row sqlcpg.GetAddressSecretRow) (*AddressSecret, error) {

	return addressSecretRowToSecret(addressSecretRow{
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
func pgAddressRowToInfo[T pgAddressInfoRow](row T) (*AddressInfo, error) {
	// Direct conversion works only because all constraint types have
	// identical fields. If sqlc types diverge, compilation will fail.
	base := sqlcpg.GetAddressByScriptPubKeyRow(row)

	info, err := addressRowToInfo(addressInfoRow[int16, int16]{
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
		IDToAddrType: idToAddressType[int16],
		IDToOrigin:   idToOrigin[int16],
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// pgListAddressesByAccount lists addresses filtered by wallet ID, key scope,
// and account name, with pagination support.
func pgListAddressesByAccount(ctx context.Context, q *sqlcpg.Queries,
	query ListAddressesQuery) ([]AddressInfo, error) {

	rows, err := q.ListAddressesByAccount(
		ctx, pgBuildAddressPageParams(query),
	)
	if err != nil {
		return nil, fmt.Errorf("list addresses by account: %w", err)
	}

	items := make([]AddressInfo, len(rows))
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
	q ListAddressesQuery) sqlcpg.ListAddressesByAccountParams {

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
