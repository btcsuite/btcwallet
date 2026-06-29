package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"iter"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

var _ db.AddressStore = (*Store)(nil)

// errUnknownAddressRowType is returned when an address row has an
// unrecognized concrete type.
var errUnknownAddressRowType = errors.New("unknown address row type")

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
		GetAccount:    getAccountFromKey,
		AccountParams: db.AccountKeyFromParams,
		GetAccountID: func(row sqlc.GetAccountByWalletScopeAndNameRow) int64 {
			return row.ID
		},
		GetAccountNumber: func(row sqlc.GetAccountByWalletScopeAndNameRow) (
			uint32, error) {

			return db.DerivedAddressAccountNumber(row.AccountNumber)
		},
		GetAccountIsDerived: func(
			row sqlc.GetAccountByWalletScopeAndNameRow) bool {

			return row.IsDerived
		},
		GetWalletWatchOnly: func(
			row sqlc.GetAccountByWalletScopeAndNameRow) bool {

			return row.WalletIsWatchOnly
		},
		GetAccountAddrSchema: func(
			row sqlc.GetAccountByWalletScopeAndNameRow) (
			db.ScopeAddrSchema, error) {

			return db.DerivedAddressAccountSchema(
				row.InternalTypeID, row.ExternalTypeID,
			)
		},
		GetAccountPubKey: func(
			row sqlc.GetAccountByWalletScopeAndNameRow) []byte {

			return row.PublicKey
		},
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

	err := params.ValidateBasic()
	if err != nil {
		return nil, err
	}

	var info *db.AddressInfo

	err = s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		created, err := s.createImportedAddress(ctx, qtx, params)
		if err != nil {
			return err
		}

		info = created

		return nil
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// createImportedAddress performs the imported-address write within an existing
// transaction and returns the resulting address info.
func (s *Store) createImportedAddress(ctx context.Context, qtx *sqlc.Queries,
	params db.NewImportedAddressParams) (*db.AddressInfo, error) {

	walletIsWatchOnly, err := getWalletWatchOnly(ctx, qtx, params.WalletID)
	if err != nil {
		return nil, err
	}

	err = params.ValidateWatchOnly(walletIsWatchOnly)
	if err != nil {
		return nil, err
	}

	err = db.RequireAddressPrivKeyOnSpendable(
		params.WalletID, walletIsWatchOnly, params.HasPrivateKey(),
	)
	if err != nil {
		return nil, err
	}

	row, err := qtx.CreateImportedAddress(
		ctx, createImportedAddressParams(params),
	)
	if err != nil {
		return nil, fmt.Errorf("create imported address: %w", err)
	}

	if params.HasSecretMaterial() {
		err = qtx.InsertAddressSecret(
			ctx, insertAddressSecretParams(row.ID, params),
		)
		if err != nil {
			return nil, fmt.Errorf("insert address secret: %w", err)
		}
	}

	addrID, err := db.Int64ToUint32(row.ID)
	if err != nil {
		return nil, fmt.Errorf("address ID: %w", err)
	}

	return &db.AddressInfo{
		ID:           addrID,
		AddrType:     params.AddressType,
		CreatedAt:    row.CreatedAt,
		IsImported:   true,
		ScriptPubKey: params.ScriptPubKey,
		PubKey:       params.PubKey,
		HasScript:    params.HasScript(),
		IsWatchOnly:  walletIsWatchOnly,
		IsUsed:       false,
	}, nil
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

	return func(ctx context.Context, walletID int64, accountID int64,
		addrType db.AddressType, branch uint32, index uint32,
		scriptPubKey []byte, pubKey []byte) (sqlc.CreateDerivedAddressRow,
		error) {

		row, err := qtx.CreateDerivedAddress(
			ctx, buildDerivedAddressParams(
				walletID, accountID, addrType, scriptPubKey, pubKey,
			),
		)
		if err != nil {
			return sqlc.CreateDerivedAddressRow{}, err
		}

		branchNum, err := db.Uint32ToInt16(branch)
		if err != nil {
			return sqlc.CreateDerivedAddressRow{},
				fmt.Errorf("address branch: %w", err)
		}

		err = qtx.CreateDerivedAddressPath(
			ctx, sqlc.CreateDerivedAddressPathParams{
				AddressID:     row.ID,
				AccountID:     accountID,
				AddressBranch: branchNum,
				AddressIndex:  int64(index),
			},
		)
		if err != nil {
			return sqlc.CreateDerivedAddressRow{}, fmt.Errorf(
				"create derived address path: %w", err,
			)
		}

		return row, nil
	}
}

// buildDerivedAddressParams maps common derived-address inputs to PostgreSQL
// sqlc insert params.
func buildDerivedAddressParams(walletID int64, accountID int64,
	addrType db.AddressType, scriptPubKey []byte,
	pubKey []byte) sqlc.CreateDerivedAddressParams {

	return sqlc.CreateDerivedAddressParams{
		WalletID:     walletID,
		AccountID:    accountID,
		ScriptPubKey: scriptPubKey,
		ScriptTypeID: int16(addrType),
		PubKey:       pubKey,
	}
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

// createImportedAddressParams maps imported params to sqlc params.
func createImportedAddressParams(
	params db.NewImportedAddressParams) sqlc.CreateImportedAddressParams {

	return sqlc.CreateImportedAddressParams{
		WalletID:     int64(params.WalletID),
		ScriptPubKey: params.ScriptPubKey,
		ScriptTypeID: int16(params.AddressType),
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

// applyAddressAccountMetadata copies account metadata from the account lookup
// row onto an address creation result before the write transaction commits.
func applyAddressAccountMetadata(info *db.AddressInfo,
	row sqlc.GetAccountByWalletScopeAndNameRow) error {

	return db.ApplyAddressAccountMetadata(
		info, row.AccountNumber, row.AccountName,
		row.MasterFingerprint, row.Purpose, row.CoinType,
		!row.IsDerived,
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
		sqlc.ListAddressesByScriptPubKeysRow |
		sqlc.ListRawImportedAddressesRow
}

// addressRowToInfo converts a PostgreSQL address row to an AddressInfo struct.
func addressRowToInfo[T addressInfoRow](row T) (*db.AddressInfo, error) {
	switch base := any(row).(type) {
	case sqlc.GetAddressByScriptPubKeyRow:
		return addressFieldsToInfo(
			base.ID, base.DerivedAddressID, base.AccountID,
			base.AccountNumber, base.AccountName, base.MasterFingerprint,
			base.Purpose, base.CoinType, base.ScriptTypeID,
			base.AddressBranch, base.AddressIndex, base.IsDerived,
			base.AccountIsDerived, base.ScriptPubKey,
			base.PubKey, base.CreatedAt,
			base.WalletIsWatchOnly, base.HasScript, base.IsUsed,
		)

	case sqlc.ListAddressesByScriptPubKeysRow:
		return addressFieldsToInfo(
			base.ID, base.DerivedAddressID, base.AccountID,
			base.AccountNumber, base.AccountName, base.MasterFingerprint,
			base.Purpose, base.CoinType, base.ScriptTypeID,
			base.AddressBranch, base.AddressIndex, base.IsDerived,
			base.AccountIsDerived, base.ScriptPubKey,
			base.PubKey, base.CreatedAt,
			base.WalletIsWatchOnly, base.HasScript, base.IsUsed,
		)

	case sqlc.ListRawImportedAddressesRow:
		return addressFieldsToInfo(
			base.ID, base.DerivedAddressID, base.AccountID,
			base.AccountNumber, base.AccountName, base.MasterFingerprint,
			base.Purpose, base.CoinType, base.ScriptTypeID,
			base.AddressBranch, base.AddressIndex, base.IsDerived,
			base.AccountIsDerived, base.ScriptPubKey,
			base.PubKey, base.CreatedAt,
			base.WalletIsWatchOnly, base.HasScript, base.IsUsed,
		)

	case sqlc.ListAddressesByAccountRow:
		return addressFieldsToInfo(
			base.ID,
			sql.NullInt64{Int64: base.DerivedAddressID, Valid: true},
			sql.NullInt64{Int64: base.AccountID, Valid: true},
			base.AccountNumber,
			sql.NullString{String: base.AccountName, Valid: true},
			base.MasterFingerprint,
			sql.NullInt64{Int64: base.Purpose, Valid: true},
			sql.NullInt64{Int64: base.CoinType, Valid: true},
			base.ScriptTypeID,
			sql.NullInt16{Int16: base.AddressBranch, Valid: true},
			sql.NullInt64{Int64: base.AddressIndex, Valid: true},
			base.IsDerived,
			sql.NullBool{Bool: base.AccountIsDerived, Valid: true},
			base.ScriptPubKey, base.PubKey, base.CreatedAt,
			base.WalletIsWatchOnly, base.HasScript, base.IsUsed,
		)

	default:
		return nil, fmt.Errorf("%w: %T", errUnknownAddressRowType, row)
	}
}

// addressFieldsToInfo converts common PostgreSQL address query fields to
// AddressInfo.
func addressFieldsToInfo(id int64, derivedAddressID sql.NullInt64,
	accountID sql.NullInt64, accountNumber sql.NullInt64,
	accountName sql.NullString, masterFingerprint sql.NullInt64,
	purpose sql.NullInt64, coinType sql.NullInt64,
	scriptTypeID int16, addressBranch sql.NullInt16,
	addressIndex sql.NullInt64, isDerived bool,
	accountIsDerived sql.NullBool, scriptPubKey []byte, pubKey []byte,
	createdAt time.Time, walletIsWatchOnly bool,
	hasScript bool, isUsed bool) (*db.AddressInfo, error) {

	branch := sql.NullInt64{
		Int64: int64(addressBranch.Int16),
		Valid: addressBranch.Valid,
	}

	return db.AddressRowToInfo(db.AddressInfoRow[int16]{
		ID:                id,
		DerivedAddressID:  derivedAddressID,
		AccountID:         accountID,
		AccountNumber:     accountNumber,
		AccountName:       accountName,
		MasterFingerprint: masterFingerprint,
		Purpose:           purpose,
		CoinType:          coinType,
		TypeID:            scriptTypeID,
		IsDerived:         isDerived,
		AccountIsDerived:  accountIsDerived,
		WalletIsWatchOnly: walletIsWatchOnly,
		HasScript:         hasScript,
		CreatedAt:         createdAt,
		AddressBranch:     branch,
		AddressIndex:      addressIndex,
		ScriptPubKey:      scriptPubKey,
		PubKey:            pubKey,
		IsUsed:            isUsed,
		IDToAddrType:      db.IDToAddressType[int16],
	})
}

// listAddressesByAccount lists addresses filtered by wallet ID, key scope,
// and account name, with pagination support.
func listAddressesByAccount(ctx context.Context, q *sqlc.Queries,
	query db.ListAddressesQuery) ([]db.AddressInfo, error) {

	if query.Scope == nil && query.AccountName == nil {
		return listRawImportedAddresses(ctx, q, query)
	}

	if query.Scope == nil || query.AccountName == nil {
		return nil, db.ErrInvalidListAddressesQuery
	}

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

// listRawImportedAddresses lists raw imported addresses for the imported alias.
func listRawImportedAddresses(ctx context.Context, q *sqlc.Queries,
	query db.ListAddressesQuery) ([]db.AddressInfo, error) {

	rows, err := q.ListRawImportedAddresses(
		ctx, sqlc.ListRawImportedAddressesParams{
			WalletID:  int64(query.WalletID),
			PageLimit: int64(query.Page.Limit()) + 1,
			CursorID:  rawAddressCursor(query),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list raw imported addresses: %w", err)
	}

	items := make([]db.AddressInfo, len(rows))
	for i, row := range rows {
		item, err := addressRowToInfo(row)
		if err != nil {
			return nil, fmt.Errorf("list raw imported addresses: %w", err)
		}

		items[i] = *item
	}

	return items, nil
}

// rawAddressCursor converts an optional page cursor into a nullable sqlc value.
func rawAddressCursor(q db.ListAddressesQuery) sql.NullInt64 {
	if q.Page.After == nil {
		return sql.NullInt64{}
	}

	return sql.NullInt64{
		Int64: int64(*q.Page.After),
		Valid: true,
	}
}

// buildAddressPageParams translates a ListAddresses query to
// ListAddressesByAccount parameters, handling pagination cursors.
func buildAddressPageParams(
	q db.ListAddressesQuery) sqlc.ListAddressesByAccountParams {

	params := sqlc.ListAddressesByAccountParams{
		WalletID:    int64(q.WalletID),
		Purpose:     int64(q.Scope.Purpose),
		CoinType:    int64(q.Scope.Coin),
		AccountName: *q.AccountName,
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
