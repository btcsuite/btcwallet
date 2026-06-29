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

	var info *db.AddressInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		getByScript := func(ctx context.Context,
			query db.GetAddressQuery) (*db.AddressInfo, error) {

			return db.GetAddress(
				ctx, q.GetAddressByScriptPubKey,
				sqlc.GetAddressByScriptPubKeyParams{
					WalletID:     int64(query.WalletID),
					ScriptPubKey: query.ScriptPubKey,
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
			ctx, getSecret, query,
			addressSecretRowToSecret,
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
		GetAccountIsDerived:  derivedAddressGetAccountIsDerived,
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
		Origin:       db.ImportedAccount,
		IsImported:   true,
		ScriptPubKey: params.ScriptPubKey,
		PubKey:       params.PubKey,
		HasScript:    params.HasScript(),
		IsWatchOnly:  walletIsWatchOnly,
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
func derivedAddressCreateAddr(qtx *sqlc.Queries) func(
	context.Context, int64, int64, db.AddressType, uint32, uint32, []byte,
	[]byte) (sqlc.CreateDerivedAddressRow, error) {

	return func(ctx context.Context, walletID int64, accountID int64,
		addrType db.AddressType, branch uint32, index uint32,
		scriptPubKey []byte,
		pubKey []byte) (sqlc.CreateDerivedAddressRow, error) {

		params, err := buildDerivedAddressParams(
			walletID, accountID, addrType, branch, index, scriptPubKey,
			pubKey,
		)
		if err != nil {
			return sqlc.CreateDerivedAddressRow{}, err
		}

		row, err := qtx.CreateDerivedAddress(ctx, params)
		if err != nil {
			return sqlc.CreateDerivedAddressRow{}, err
		}

		err = qtx.CreateDerivedAddressPath(
			ctx, sqlc.CreateDerivedAddressPathParams{
				AccountID:     accountID,
				AddressBranch: params.AddressBranch.Int64,
				AddressIndex:  params.AddressIndex.Int64,
				AddressID:     row.ID,
				WalletID:      walletID,
			},
		)
		if err != nil {
			return sqlc.CreateDerivedAddressRow{},
				fmt.Errorf("create derived address path: %w", err)
		}

		return row, nil
	}
}

// buildDerivedAddressParams maps common derived-address inputs to SQLite sqlc
// insert params.
func buildDerivedAddressParams(walletID int64, accountID int64,
	addrType db.AddressType, branch uint32, index uint32,
	scriptPubKey []byte,
	pubKey []byte) (sqlc.CreateDerivedAddressParams, error) {

	return sqlc.CreateDerivedAddressParams{
		WalletID: walletID,
		AccountID: sql.NullInt64{
			Int64: accountID,
			Valid: true,
		},
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
		PubKey: pubKey,
	}, nil
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
func createImportedAddressParams(
	params db.NewImportedAddressParams) sqlc.CreateImportedAddressParams {

	return sqlc.CreateImportedAddressParams{
		WalletID:     int64(params.WalletID),
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

// applyAddressAccountMetadata copies account metadata from the account lookup
// row onto an address creation result before the write transaction commits.
func applyAddressAccountMetadata(info *db.AddressInfo,
	row sqlc.GetAccountByWalletScopeAndNameRow) error {

	return db.ApplyAddressAccountMetadata(
		info, row.AccountNumber, row.AccountName,
		row.MasterFingerprint, row.Purpose, row.CoinType,
		row.OriginID == int64(db.ImportedAccount),
	)
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
		sqlc.ListAddressesByAccountRow |
		sqlc.ListAddressesByScriptPubKeysRow |
		sqlc.ListRawImportedAddressesRow
}

// addressRowToInfo converts a SQLite address row to an AddressInfo struct.
func addressRowToInfo[T addressInfoRow](row T) (*db.AddressInfo, error) {
	switch base := any(row).(type) {
	case sqlc.GetAddressByScriptPubKeyRow:
		return addressFieldsToInfo(
			base.ID, base.AccountID, base.AccountNumber,
			base.AccountName, base.MasterFingerprint,
			base.Purpose, base.CoinType, base.TypeID,
			base.OriginID, base.IsDerived, base.WalletIsWatchOnly,
			base.HasScript, base.CreatedAt, base.AddressBranch,
			base.AddressIndex, base.ScriptPubKey, base.PubKey,
			base.IsUsed,
		)

	case sqlc.ListAddressesByAccountRow:
		addressBranch := sql.NullInt64{
			Int64: base.AddressBranch,
			Valid: true,
		}
		addressIndex := sql.NullInt64{
			Int64: base.AddressIndex,
			Valid: true,
		}

		return addressFieldsToInfo(
			base.ID, base.AccountID, base.AccountNumber,
			base.AccountName, base.MasterFingerprint,
			base.Purpose, base.CoinType, base.TypeID,
			base.OriginID, base.IsDerived, base.WalletIsWatchOnly,
			base.HasScript, base.CreatedAt,
			addressBranch, addressIndex, base.ScriptPubKey,
			base.PubKey, base.IsUsed,
		)

	case sqlc.ListAddressesByScriptPubKeysRow:
		return addressFieldsToInfo(
			base.ID, base.AccountID, base.AccountNumber,
			base.AccountName, base.MasterFingerprint,
			base.Purpose, base.CoinType, base.TypeID,
			base.OriginID, base.IsDerived, base.WalletIsWatchOnly,
			base.HasScript, base.CreatedAt, base.AddressBranch,
			base.AddressIndex, base.ScriptPubKey, base.PubKey,
			base.IsUsed,
		)

	case sqlc.ListRawImportedAddressesRow:
		accountNumber, err := nullableInt64(base.AccountNumber)
		if err != nil {
			return nil, fmt.Errorf("account number: %w", err)
		}

		masterFingerprint, err := nullableInt64(base.MasterFingerprint)
		if err != nil {
			return nil, fmt.Errorf("master fingerprint: %w", err)
		}

		addressBranch, err := nullableInt64(base.AddressBranch)
		if err != nil {
			return nil, fmt.Errorf("address branch: %w", err)
		}

		addressIndex, err := nullableInt64(base.AddressIndex)
		if err != nil {
			return nil, fmt.Errorf("address index: %w", err)
		}

		return addressFieldsToInfo(
			base.ID, base.AccountID, accountNumber,
			base.AccountName, masterFingerprint,
			base.Purpose, base.CoinType, base.TypeID,
			base.OriginID, base.IsDerived, base.WalletIsWatchOnly,
			base.HasScript, base.CreatedAt, addressBranch,
			addressIndex, base.ScriptPubKey, base.PubKey, base.IsUsed,
		)

	default:
		return nil, fmt.Errorf("unknown address row type: %T", row)
	}
}

// nullableInt64 converts SQLite interface-backed nullable integers to
// sql.NullInt64.
func nullableInt64(value any) (sql.NullInt64, error) {
	switch v := value.(type) {
	case nil:
		return sql.NullInt64{}, nil

	case int64:
		return sql.NullInt64{
			Int64: v,
			Valid: true,
		}, nil

	default:
		return sql.NullInt64{}, fmt.Errorf("unexpected type %T", value)
	}
}

// addressFieldsToInfo converts SQLite address query fields into an AddressInfo
// struct.
func addressFieldsToInfo(id int64, accountID int64,
	accountNumber sql.NullInt64, accountName string,
	masterFingerprint sql.NullInt64, purpose int64, coinType int64,
	typeID int64, originID int64, isDerived bool, walletIsWatchOnly bool,
	hasScript bool, createdAt time.Time, addressBranch sql.NullInt64,
	addressIndex sql.NullInt64, scriptPubKey []byte, pubKey []byte,
	isUsed bool) (*db.AddressInfo, error) {

	return db.AddressRowToInfo(db.AddressInfoRow[int64, int64]{
		ID:                id,
		AccountID:         accountID,
		AccountNumber:     accountNumber,
		AccountName:       accountName,
		IsDerived:         isDerived,
		MasterFingerprint: masterFingerprint,
		Purpose:           purpose,
		CoinType:          coinType,
		TypeID:            typeID,
		OriginID:          originID,
		WalletIsWatchOnly: walletIsWatchOnly,
		HasScript:         hasScript,
		CreatedAt:         createdAt,
		AddressBranch:     addressBranch,
		AddressIndex:      addressIndex,
		ScriptPubKey:      scriptPubKey,
		PubKey:            pubKey,
		IsUsed:            isUsed,
		IDToAddrType:      db.IDToAddressType[int64],
		IDToOrigin:        db.IDToOrigin[int64],
	})
}

// listAddressesByAccount lists addresses filtered by wallet ID, key
// scope, and account name, with pagination support.
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

// rawAddressCursor converts an optional page cursor into a sqlc value.
func rawAddressCursor(q db.ListAddressesQuery) any {
	if q.Page.After == nil {
		return nil
	}

	return int64(*q.Page.After)
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
		params.CursorID = int64(*q.Page.After)
	}

	return params
}
