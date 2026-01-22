package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// GetAddress retrieves information about a specific address, identified by
// its script pubkey.
func (w *PostgresWalletDB) GetAddress(ctx context.Context,
	query GetAddressQuery) (*AddressInfo, error) {

	getByScript := func(ctx context.Context, q GetAddressQuery) (*AddressInfo,
		error) {

		return getAddress(
			ctx, w.queries.GetAddressByScriptPubKey,
			sqlcpg.GetAddressByScriptPubKeyParams{
				ScriptPubKey: q.ScriptPubKey,
				WalletID:     int64(q.WalletID),
			}, pgAddressRowToInfo,
		)
	}

	return getAddressByQuery(ctx, query, getByScript)
}

// ListAddresses returns a slice of AddressInfo for all addresses in a given
// account.
func (w *PostgresWalletDB) ListAddresses(ctx context.Context,
	query ListAddressesQuery) ([]AddressInfo, error) {

	return listAddresses(
		ctx, w.queries.ListAddressesByAccount,
		sqlcpg.ListAddressesByAccountParams{
			WalletID:    int64(query.WalletID),
			Purpose:     int64(query.Scope.Purpose),
			CoinType:    int64(query.Scope.Coin),
			AccountName: query.AccountName,
		}, pgAddressRowToInfo,
	)
}

// GetAddressSecret retrieves the encrypted secret information for an address.
func (w *PostgresWalletDB) GetAddressSecret(ctx context.Context,
	addressID uint32) (*AddressSecret, error) {

	return getAddressSecret(
		ctx, w.queries.GetAddressSecret, addressID, pgAddressSecretRowToSecret,
	)
}

// NewDerivedAddress creates a new address for a given account and key
// scope.
func (w *PostgresWalletDB) NewDerivedAddress(ctx context.Context,
	params NewDerivedAddressParams,
	deriveFn AddressDerivationFunc) (*AddressInfo, error) {

	adapters := derivedAddressAdapters[
		*sqlcpg.Queries,
		sqlcpg.GetAccountByWalletScopeAndNameRow,
		accountLookupKey,
		sqlcpg.CreateDerivedAddressRow]{
		getAccount:    pgGetAccountFromKey(w.queries),
		accountParams: accountKeyFromParams,
		getAccountID:  newDerivedAddressGetAccountIDPg,
		getExtIndex:   newDerivedAddressGetExtIndexPg,
		getIntIndex:   newDerivedAddressGetIntIndexPg,
		createAddr:    newDerivedAddressCreateAddrPg,
		rowID:         newDerivedAddressRowIDPg,
		rowCreatedAt:  newDerivedAddressRowCreatedAtPg,
	}

	return newDerivedAddressWithTx(ctx, params, w.ExecuteTx, adapters, deriveFn)
}

// NewImportedAddress imports a new address, script, or private key.
func (w *PostgresWalletDB) NewImportedAddress(ctx context.Context,
	params NewImportedAddressParams) (*AddressInfo, error) {

	adapters := importedAddressAdapters[
		*sqlcpg.Queries,
		sqlcpg.GetAccountByWalletScopeAndNameRow,
		accountLookupKey,
		sqlcpg.CreateImportedAddressParams,
		sqlcpg.CreateImportedAddressRow,
		sqlcpg.InsertAddressSecretParams]{
		getAccount:    pgGetAccountFromKey(w.queries),
		accountParams: accountKeyFromImportedParams,
		getAccountID:  newImportedAddressGetAccountIDPg,
		createAddr:    pgCreateImportedAddress,
		createParams:  createImportedAddressParamsPg,
		insertSecret:  pgInsertAddressSecret,
		secretParams:  insertAddressSecretParamsPg,
		rowID:         importedAddressRowIDPg,
		rowCreatedAt:  importedAddressRowCreatedAtPg,
	}

	return newImportedAddressWithTx(ctx, params, w.ExecuteTx, adapters)
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

		return qtx.CreateDerivedAddress(
			ctx, sqlcpg.CreateDerivedAddressParams{
				AccountID:    accountID,
				ScriptPubKey: scriptPubKey,
				TypeID:       int16(addrType),
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

// pgAddressSecretRowToSecret converts a sqlc GetAddressSecretRow row to the
// db.AddressSecret type used by the wallet, handling null value conversions.
// Returns ErrSecretNotFound if the address exists but has no secret.
func pgAddressSecretRowToSecret(row sqlcpg.GetAddressSecretRow) (*AddressSecret,
	error) {

	hasKey := len(row.EncryptedPrivKey) > 0
	hasScript := len(row.EncryptedScript) > 0

	if !hasKey && !hasScript {
		return nil, fmt.Errorf("address %d: %w", row.AddressID,
			ErrSecretNotFound)
	}

	addrID, err := int64ToUint32(row.AddressID)
	if err != nil {
		return nil, fmt.Errorf("address ID: %w", err)
	}

	return &AddressSecret{
		AddressID:        addrID,
		EncryptedPrivKey: row.EncryptedPrivKey,
		EncryptedScript:  row.EncryptedScript,
	}, nil
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
		AddressBranch: base.AddressBranch,
		AddressIndex:  base.AddressIndex,
		ScriptPubKey:  base.ScriptPubKey,
		PubKey:        base.PubKey,
		IDToAddrType:  idToAddressType[int16],
		IDToOrigin:    idToOrigin[int16],
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}
