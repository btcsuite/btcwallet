package pg

import (
	"context"
	"database/sql"
	"fmt"
	"iter"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

var _ db.AddressStore = (*Store)(nil)

// GetAddress retrieves information about a specific address, identified by
// its script pubkey.
func (s *Store) GetAddress(ctx context.Context,
	query db.GetAddressQuery) (*db.AddressInfo, error) {

	var info *db.AddressInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		getByScript := func(ctx context.Context,
			query db.GetAddressQuery) (*db.AddressInfo, error) {

			return db.GetAddress(
				ctx, q.GetAddressByScriptPubKey,
				sqlc.GetAddressByScriptPubKeyParams{
					ScriptPubKey: query.ScriptPubKey,
					WalletID:     int64(query.WalletID),
				}, addressRowToInfo,
			)
		}

		var err error

		info, err = db.GetAddressByQuery(ctx, query, getByScript)

		return err
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// ResolveOwnedAddresses resolves a batch of script pubkeys to the wallet-owned
// subset using a single query.
func (s *Store) ResolveOwnedAddresses(ctx context.Context,
	query db.ResolveOwnedAddressesQuery) (map[string]*db.AddressInfo, error) {

	owned := make(map[string]*db.AddressInfo)

	// An empty request resolves to an empty result without issuing a query.
	if len(query.ScriptPubKeys) == 0 {
		return owned, nil
	}

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		rows, err := q.ListAddressesByScriptPubKeys(
			ctx, sqlc.ListAddressesByScriptPubKeysParams{
				WalletID:      int64(query.WalletID),
				ScriptPubKeys: query.ScriptPubKeys,
			},
		)
		if err != nil {
			return fmt.Errorf("list addresses by scripts: %w", err)
		}

		for _, row := range rows {
			info, err := addressRowToInfo(row)
			if err != nil {
				return fmt.Errorf("map address row: %w", err)
			}

			owned[string(info.ScriptPubKey)] = info
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return owned, nil
}

// ListAddresses returns a page of addresses matching the given query.
func (s *Store) ListAddresses(ctx context.Context,
	query db.ListAddressesQuery) (page.Result[db.AddressInfo, uint32], error) {

	if query.Page.Limit() == 0 {
		return page.Result[db.AddressInfo, uint32]{}, db.ErrInvalidPageLimit
	}

	var items []db.AddressInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		var err error

		items, err = listAddressesByAccount(ctx, q, query)

		return err
	})
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
	query db.GetAddressSecretQuery) (*db.AddressSecret, error) {

	getSecret := func(ctx context.Context, walletID int64,
		addressID int64) (sqlc.GetAddressSecretRow, error) {

		return s.queries.GetAddressSecret(
			ctx, sqlc.GetAddressSecretParams{
				WalletID: walletID,
				ID:       addressID,
			},
		)
	}

	var secret *db.AddressSecret

	err := s.execRead(ctx, func(_ *sqlc.Queries) error {
		var err error

		secret, err = db.GetAddressSecret(
			ctx, getSecret, query, addressSecretRowToSecret,
		)

		return err
	})
	if err != nil {
		return nil, err
	}

	return secret, nil
}

// NewDerivedAddress creates a new address for a given account and key
// scope.
func (s *Store) NewDerivedAddress(ctx context.Context,
	params db.NewDerivedAddressParams) (*db.AddressInfo, error) {

	adapters := db.DerivedAddressAdapters[
		*sqlc.Queries,
		sqlc.GetAccountByWalletScopeAndNameRow,
		db.AccountLookupKey,
		sqlc.CreateDerivedAddressRow]{
		GetAccount:           getAccountFromKey(s.queries),
		AccountParams:        db.AccountKeyFromParams,
		GetAccountID:         derivedAddressGetAccountID,
		GetAccountNumber:     derivedAddressGetAccountNumber,
		GetWalletWatchOnly:   derivedAddressGetWalletWatchOnly,
		GetAccountAddrSchema: derivedAddressGetAccountAddrSchema,
		GetAccountPubKey:     derivedAddressGetAccountPubKey,
		GetExtIndex:          derivedAddressGetExtIndex,
		GetIntIndex:          derivedAddressGetIntIndex,
		CreateAddr:           derivedAddressCreateAddr,
		RowID:                derivedAddressRowID,
		RowCreatedAt:         derivedAddressRowCreatedAt,
		ApplyAccountMetadata: applyAddressAccountMetadata,
	}

	return db.NewDerivedAddressWithTx(
		ctx, params, s.execWrite, adapters, s.deriveAddress,
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
		GetAccount:           getAccountFromKey(s.queries),
		AccountParams:        db.AccountKeyFromImportedParams,
		CreateBucketAccount:  createImportedBucketAccount,
		GetAccountID:         importedAddressGetAccountID,
		GetWalletWatchOnly:   importedAddressGetWalletWatchOnly,
		CreateAddr:           createImportedAddress,
		CreateParams:         createImportedAddressParams,
		InsertSecret:         insertAddressSecret,
		SecretParams:         insertAddressSecretParams,
		RowID:                importedAddressRowID,
		RowCreatedAt:         importedAddressRowCreatedAt,
		ApplyAccountMetadata: applyAddressAccountMetadata,
	}

	return db.NewImportedAddressWithTx(
		ctx, params, s.execWrite, adapters,
	)
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

// derivedAddressGetExtIndex returns the external index query.
func derivedAddressGetExtIndex(qtx *sqlc.Queries) func(context.Context,
	int64) (int64, error) {

	return qtx.GetAndIncrementNextExternalIndex
}

// derivedAddressGetIntIndex returns the internal index query.
func derivedAddressGetIntIndex(qtx *sqlc.Queries) func(context.Context,
	int64) (int64, error) {

	return qtx.GetAndIncrementNextInternalIndex
}

// derivedAddressCreateAddr returns the derived address insert helper.
func derivedAddressCreateAddr(qtx *sqlc.Queries) func(
	context.Context, int64, int64, db.AddressType, uint32, uint32, []byte,
	[]byte) (sqlc.CreateDerivedAddressRow, error) {

	return db.DerivedAddressCreateAddr(
		qtx.CreateDerivedAddress, buildDerivedAddressParams,
	)
}

// buildDerivedAddressParams maps common derived-address inputs to PostgreSQL
// sqlc insert params.
func buildDerivedAddressParams(walletID int64, accountID int64,
	addrType db.AddressType, branch uint32, index uint32,
	scriptPubKey []byte,
	pubKey []byte) (sqlc.CreateDerivedAddressParams, error) {

	branchNum, err := db.Uint32ToInt16(branch)
	if err != nil {
		return sqlc.CreateDerivedAddressParams{},
			fmt.Errorf("address branch: %w", err)
	}

	return sqlc.CreateDerivedAddressParams{
		WalletID:     walletID,
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
		PubKey: pubKey,
	}, nil
}

// derivedAddressRowID returns the created address ID.
func derivedAddressRowID(row sqlc.CreateDerivedAddressRow) int64 {
	return row.ID
}

// derivedAddressRowCreatedAt returns the CreatedAt timestamp.
func derivedAddressRowCreatedAt(
	row sqlc.CreateDerivedAddressRow) time.Time {

	return row.CreatedAt
}

// createImportedBucketAccount materializes the keyless wallet-level imported
// bucket account for the import's scope inside the active write transaction
// and returns the freshly looked-up account row. The bucket carries empty
// account-level key material (no public key, no master fingerprint) and no
// account_secrets row: it is a holder for individually-imported addresses, not
// an imported xpub account. The key scope is created on demand using its
// default address schema if it does not already exist.
//
// Materialization is an idempotent get-or-create: the insert uses ON CONFLICT
// DO NOTHING so concurrent first-imports into the same scope cannot collide on
// the (scope_id, account_name) unique index, and the row is always re-read
// through GetAccountByWalletScopeAndName afterwards. The re-read both yields a
// row whose shape matches the existing-bucket lookup path exactly and returns
// the surviving bucket when this call was the no-op loser of a race.
func createImportedBucketAccount(ctx context.Context, qtx *sqlc.Queries,
	params db.NewImportedAddressParams) (
	sqlc.GetAccountByWalletScopeAndNameRow, error) {

	var zero sqlc.GetAccountByWalletScopeAndNameRow

	scopeID, _, err := ensureKeyScope(
		ctx, qtx, params.WalletID, params.Scope, nil,
	)
	if err != nil {
		return zero, fmt.Errorf("ensure scope: %w", err)
	}

	// ON CONFLICT DO NOTHING makes this a get-or-create: a concurrent
	// first-import that already materialized the bucket is a no-op here,
	// and the re-read below returns the existing row.
	err = qtx.CreateImportedBucketAccount(
		ctx, sqlc.CreateImportedBucketAccountParams{
			ScopeID:     scopeID,
			AccountName: db.DefaultImportedAccountName,
			OriginID:    int16(db.ImportedAccount),
		},
	)
	if err != nil {
		return zero, fmt.Errorf("create bucket account: %w", err)
	}

	return getAccountFromKey(qtx)(
		ctx, db.AccountKeyFromImportedParams(params),
	)
}

// createImportedAddress returns the imported address insert helper.
func createImportedAddress(qtx *sqlc.Queries) func(context.Context,
	sqlc.CreateImportedAddressParams) (sqlc.CreateImportedAddressRow,
	error) {

	return qtx.CreateImportedAddress
}

// insertAddressSecret returns the secret insert helper.
func insertAddressSecret(qtx *sqlc.Queries) func(context.Context,
	sqlc.InsertAddressSecretParams) error {

	return qtx.InsertAddressSecret
}

// createImportedAddressParams maps imported params to sqlc params.
func createImportedAddressParams(walletID int64, accountID int64,
	params db.NewImportedAddressParams) sqlc.CreateImportedAddressParams {

	return sqlc.CreateImportedAddressParams{
		WalletID:     walletID,
		AccountID:    accountID,
		ScriptPubKey: params.ScriptPubKey,
		TypeID:       int16(params.AddressType),
		PubKey:       params.PubKey,
	}
}

// insertAddressSecretParams maps imported params to secret params.
func insertAddressSecretParams(addressID int64,
	params db.NewImportedAddressParams) sqlc.InsertAddressSecretParams {

	return sqlc.InsertAddressSecretParams{
		AddressID: addressID,
		EncryptedPrivKey: db.NilIfEmptyBytes(
			params.EncryptedPrivateKey,
		),
		EncryptedScript: db.NilIfEmptyBytes(
			params.EncryptedScript,
		),
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

// applyAddressAccountMetadata copies account metadata from the account lookup
// row onto an address creation result before the write transaction commits.
func applyAddressAccountMetadata(info *db.AddressInfo,
	row sqlc.GetAccountByWalletScopeAndNameRow) error {

	return db.ApplyAddressAccountMetadata(
		info, row.AccountNumber, row.AccountName,
		row.MasterFingerprint, row.Purpose, row.CoinType,
	)
}

// addressSecretRowToSecret converts a PostgreSQL address secret row to an
// AddressSecret struct.
func addressSecretRowToSecret(
	row sqlc.GetAddressSecretRow) (*db.AddressSecret, error) {

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
	sqlc.GetAddressByScriptPubKeyRow |
		sqlc.ListAddressesByAccountRow |
		sqlc.ListAddressesByScriptPubKeysRow
}

// addressRowToInfo converts a PostgreSQL address row to an AddressInfo struct.
func addressRowToInfo[T addressInfoRow](row T) (*db.AddressInfo, error) {
	// Direct conversion works only because all constraint types have
	// identical fields. If sqlc types diverge, compilation will fail.
	base := sqlc.GetAddressByScriptPubKeyRow(row)

	info, err := db.AddressRowToInfo(db.AddressInfoRow[int16, int16]{
		ID:                base.ID,
		AccountID:         base.AccountID,
		AccountNumber:     base.AccountNumber,
		AccountName:       base.AccountName,
		MasterFingerprint: base.MasterFingerprint,
		Purpose:           base.Purpose,
		CoinType:          base.CoinType,
		TypeID:            base.TypeID,
		OriginID:          base.OriginID,
		WalletIsWatchOnly: base.WalletIsWatchOnly,
		HasScript:         base.HasScript,
		CreatedAt:         base.CreatedAt,
		AddressBranch: sql.NullInt64{
			Int64: int64(base.AddressBranch.Int16),
			Valid: base.AddressBranch.Valid,
		},
		AddressIndex: base.AddressIndex,
		ScriptPubKey: base.ScriptPubKey,
		PubKey:       base.PubKey,
		IsUsed:       base.IsUsed,
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
		params.CursorID = sql.NullInt64{
			Int64: int64(*q.Page.After),
			Valid: true,
		}
	}

	return params
}
