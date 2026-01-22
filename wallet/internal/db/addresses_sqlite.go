package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// GetAddress retrieves information about a specific address, identified by
// its script pubkey.
func (w *SQLiteWalletDB) GetAddress(ctx context.Context,
	query GetAddressQuery) (*AddressInfo, error) {

	getByScript := func(ctx context.Context, q GetAddressQuery) (*AddressInfo,
		error) {

		return getAddress(
			ctx, w.queries.GetAddressByScriptPubKey,
			sqlcsqlite.GetAddressByScriptPubKeyParams{
				WalletID:     int64(q.WalletID),
				ScriptPubKey: q.ScriptPubKey,
			}, sqliteAddressRowToInfo,
		)
	}

	return getAddressByQuery(ctx, query, getByScript)
}

// ListAddresses returns a slice of AddressInfo for all addresses in a given
// account.
func (w *SQLiteWalletDB) ListAddresses(ctx context.Context,
	query ListAddressesQuery) ([]AddressInfo, error) {

	return listAddresses(
		ctx, w.queries.ListAddressesByAccount,
		sqlcsqlite.ListAddressesByAccountParams{
			WalletID:    int64(query.WalletID),
			Purpose:     int64(query.Scope.Purpose),
			CoinType:    int64(query.Scope.Coin),
			AccountName: query.AccountName,
		}, sqliteAddressRowToInfo,
	)
}

// GetAddressSecret retrieves the encrypted secret information for an address.
func (w *SQLiteWalletDB) GetAddressSecret(ctx context.Context,
	addressID uint32) (*AddressSecret, error) {

	return getAddressSecret(
		ctx, w.queries.GetAddressSecret, addressID,
		sqliteAddressSecretRowToSecret,
	)
}

// NewDerivedAddress creates a new address for a given account and key
// scope.
func (w *SQLiteWalletDB) NewDerivedAddress(ctx context.Context,
	params NewDerivedAddressParams,
	deriveFn AddressDerivationFunc) (*AddressInfo, error) {

	adapters := derivedAddressAdapters[
		*sqlcsqlite.Queries,
		sqlcsqlite.GetAccountByWalletScopeAndNameRow,
		accountLookupKey,
		sqlcsqlite.CreateDerivedAddressRow]{
		getAccount:    sqliteGetAccountFromKey(w.queries),
		accountParams: accountKeyFromParams,
		getAccountID:  newDerivedAddressGetAccountIDSQLite,
		getExtIndex:   newDerivedAddressGetExtIndexSQLite,
		getIntIndex:   newDerivedAddressGetIntIndexSQLite,
		createAddr:    newDerivedAddressCreateAddrSQLite,
		rowID:         newDerivedAddressRowIDSQLite,
		rowCreatedAt:  newDerivedAddressRowCreatedAtSQLite,
	}

	return newDerivedAddressWithTx(ctx, params, w.ExecuteTx, adapters, deriveFn)
}

// NewImportedAddress imports a new address, script, or private key.
func (w *SQLiteWalletDB) NewImportedAddress(ctx context.Context,
	params NewImportedAddressParams) (*AddressInfo, error) {

	adapters := importedAddressAdapters[
		*sqlcsqlite.Queries,
		sqlcsqlite.GetAccountByWalletScopeAndNameRow,
		accountLookupKey,
		sqlcsqlite.CreateImportedAddressParams,
		sqlcsqlite.CreateImportedAddressRow,
		sqlcsqlite.InsertAddressSecretParams]{
		getAccount:    sqliteGetAccountFromKey(w.queries),
		accountParams: accountKeyFromImportedParams,
		getAccountID:  newImportedAddressGetAccountIDSQLite,
		createAddr:    sqliteCreateImportedAddress,
		createParams:  createImportedAddressParamsSQLite,
		insertSecret:  sqliteInsertAddressSecret,
		secretParams:  insertAddressSecretParamsSQLite,
		rowID:         importedAddressRowIDSQLite,
		rowCreatedAt:  importedAddressRowCreatedAtSQLite,
	}

	return newImportedAddressWithTx(ctx, params, w.ExecuteTx, adapters)
}

// sqliteGetAccountFromKey returns a helper to look up accounts by key.
func sqliteGetAccountFromKey(qtx *sqlcsqlite.Queries) func(context.Context,
	accountLookupKey) (sqlcsqlite.GetAccountByWalletScopeAndNameRow, error) {

	return func(ctx context.Context,
		key accountLookupKey) (sqlcsqlite.GetAccountByWalletScopeAndNameRow,
		error) {

		return qtx.GetAccountByWalletScopeAndName(
			ctx, sqlcsqlite.GetAccountByWalletScopeAndNameParams{
				WalletID:    key.walletID,
				Purpose:     key.purpose,
				CoinType:    key.coinType,
				AccountName: key.accountName,
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

// sqliteAddressSecretRowToSecret converts a sqlc GetAddressSecretRow row to the
// db.AddressSecret type used by the wallet, handling null value conversions.
// Returns ErrSecretNotFound if the secret is missing.
func sqliteAddressSecretRowToSecret(
	row sqlcsqlite.GetAddressSecretRow) (*AddressSecret, error) {

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

	info, err := addressRowToInfo(addressInfoRow[int64, int64]{
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
		IDToAddrType:  idToAddressType[int64],
		IDToOrigin:    idToOrigin[int64],
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}
