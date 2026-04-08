package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"

	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// Ensure SqliteStore satisfies the AccountStore interface.
var _ db.AccountStore = (*SqliteStore)(nil)

// GetAccount retrieves information about a specific account, identified by its
// name or account number within a given key scope.
func (s *SqliteStore) GetAccount(ctx context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	getQueries := sqliteAccountGetQueries{q: s.queries}

	return db.GetAccountByQuery(
		ctx, query, getQueries.byNumber, getQueries.byName,
	)
}

// ListAccounts returns a slice of AccountInfo for all accounts, optionally
// filtered by name or key scope.
func (s *SqliteStore) ListAccounts(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	listQueries := sqliteAccountListQueries{q: s.queries}

	return db.ListAccountsByQuery(
		ctx, query, listQueries.byScope, listQueries.byName, listQueries.all,
	)
}

// RenameAccount changes the name of an account. The account can be identified
// by its old name or its account number.
func (s *SqliteStore) RenameAccount(ctx context.Context,
	params db.RenameAccountParams) error {

	renameQueries := sqliteAccountRenameQueries{q: s.queries}

	return db.RenameAccountByQuery(
		ctx, params, renameQueries.byNumber, renameQueries.byName,
	)
}

// CreateDerivedAccount creates a new derived account with the given name and
// scope. If the key scope does not exist, it is created with NULL encrypted
// keys using the address schema provided by the caller.
func (s *SqliteStore) CreateDerivedAccount(ctx context.Context,
	params db.CreateDerivedAccountParams) (*db.AccountInfo, error) {

	paramsErr := params.Validate()
	if paramsErr != nil {
		return nil, paramsErr
	}

	var info *db.AccountInfo

	err := s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		scopeID, err := sqliteEnsureKeyScope(
			ctx, qtx, params.WalletID, params.Scope,
		)
		if err != nil {
			return err
		}

		row, err := qtx.CreateDerivedAccount(
			ctx, sqlcsqlite.CreateDerivedAccountParams{
				ScopeID:     scopeID,
				AccountName: params.Name,
				OriginID:    int64(db.DerivedAccount),
				IsWatchOnly: false,
			},
		)
		if err != nil {
			return fmt.Errorf("create account: %w", err)
		}

		if !row.AccountNumber.Valid {
			// This should never happen unless the query is modified
			// incorrectly.
			return db.ErrNilDBAccountNumber
		}

		accNumber, err := db.Int64ToUint32(row.AccountNumber.Int64)
		if err != nil {
			return fmt.Errorf("%w: %w", db.ErrMaxAccountNumberReached, err)
		}

		info = db.BuildAccountInfo(
			accNumber, params.Name, db.DerivedAccount, 0, 0, 0, false,
			row.CreatedAt, params.Scope,
		)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// sqliteEnsureKeyScope retrieves an existing key scope or creates it if missing
// for SQLite. It returns the scope ID once available.
func sqliteEnsureKeyScope(ctx context.Context, qtx *sqlcsqlite.Queries,
	walletID uint32, scope db.KeyScope) (int64, error) {

	return db.EnsureKeyScope(
		ctx, qtx.GetKeyScopeByWalletAndScope,
		sqlcsqlite.GetKeyScopeByWalletAndScopeParams{
			WalletID: int64(walletID),
			Purpose:  int64(scope.Purpose),
			CoinType: int64(scope.Coin),
		}, qtx.CreateKeyScope,
		func(addrSchema db.ScopeAddrSchema) sqlcsqlite.CreateKeyScopeParams {
			return sqlcsqlite.CreateKeyScopeParams{
				WalletID:            int64(walletID),
				Purpose:             int64(scope.Purpose),
				CoinType:            int64(scope.Coin),
				EncryptedCoinPubKey: nil,
				InternalTypeID: int64(
					addrSchema.InternalAddrType,
				),
				ExternalTypeID: int64(
					addrSchema.ExternalAddrType,
				),
			}
		},
		func(row sqlcsqlite.KeyScope) int64 { return row.ID }, scope,
	)
}

// CreateImportedAccount stores an imported account identified by an extended
// public key. If the key scope does not exist, it is created with NULL
// encrypted keys using the address schema provided by the caller. Imported
// accounts have NULL account_number since they don't follow BIP44 derivation.
func (s *SqliteStore) CreateImportedAccount(ctx context.Context,
	params db.CreateImportedAccountParams) (*db.AccountProperties, error) {

	var props *db.AccountProperties

	err := s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		var err error

		props, err = db.CreateImportedAccount(
			ctx, params,
			func() (int64, error) {
				return sqliteEnsureKeyScope(
					ctx, qtx, params.WalletID, params.Scope,
				)
			},
			qtx.CreateImportedAccount,
			sqliteBuildCreateImportedAccountArgs(params),
			func(row sqlcsqlite.CreateImportedAccountRow) int64 {
				return row.ID
			},
			qtx.CreateAccountSecret, sqliteBuildCreateAccountSecretArgs(params),
			func(accountID int64) (*db.AccountProperties, error) {
				return sqliteGetAccountProps(ctx, qtx, accountID)
			},
		)

		return err
	})
	if err != nil {
		return nil, err
	}

	return props, nil
}

// sqliteBuildCreateImportedAccountArgs returns a function that builds the
// CreateImportedAccountParams for SQLite.
func sqliteBuildCreateImportedAccountArgs(
	params db.CreateImportedAccountParams,
) func(int64, bool) sqlcsqlite.CreateImportedAccountParams {

	return func(scopeID int64,
		isWatchOnly bool) sqlcsqlite.CreateImportedAccountParams {

		return sqlcsqlite.CreateImportedAccountParams{
			ScopeID:            scopeID,
			AccountName:        params.Name,
			OriginID:           int64(db.ImportedAccount),
			EncryptedPublicKey: params.EncryptedPublicKey,
			MasterFingerprint: sql.NullInt64{
				Int64: int64(params.MasterFingerprint),
				Valid: true,
			},
			IsWatchOnly: isWatchOnly,
		}
	}
}

// sqliteBuildCreateAccountSecretArgs returns a function that builds the
// CreateAccountSecretParams for SQLite.
func sqliteBuildCreateAccountSecretArgs(
	params db.CreateImportedAccountParams,
) func(int64) sqlcsqlite.CreateAccountSecretParams {

	return func(accountID int64) sqlcsqlite.CreateAccountSecretParams {
		return sqlcsqlite.CreateAccountSecretParams{
			AccountID:           accountID,
			EncryptedPrivateKey: params.EncryptedPrivateKey,
		}
	}
}

// sqliteGetAccountProps fetches full account properties from the database and
// converts the row to AccountProperties.
func sqliteGetAccountProps(ctx context.Context, qtx *sqlcsqlite.Queries,
	accountID int64) (*db.AccountProperties, error) {

	row, err := qtx.GetAccountPropsById(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("get account props: %w", err)
	}

	return db.AccountPropsRowToProps(db.AccountPropsRow[int64, int64]{
		AccountNumber:      row.AccountNumber,
		AccountName:        row.AccountName,
		OriginID:           row.OriginID,
		ExternalKeyCount:   row.ExternalKeyCount,
		InternalKeyCount:   row.InternalKeyCount,
		ImportedKeyCount:   row.ImportedKeyCount,
		EncryptedPublicKey: row.EncryptedPublicKey,
		MasterFingerprint:  row.MasterFingerprint,
		IsWatchOnly:        row.IsWatchOnly,
		CreatedAt:          row.CreatedAt,
		Purpose:            row.Purpose,
		CoinType:           row.CoinType,
		InternalTypeID:     row.InternalTypeID,
		ExternalTypeID:     row.ExternalTypeID,
		IDToAddrType:       db.IDToAddressType[int64],
		IDToOriginType:     db.IDToAccountOrigin[int64],
	})
}

// sqliteAccountInfoRow is a type constraint for SQLite account info row types
// that share the same field structure. This enables a single generic conversion
// function to handle all account query result types.
type sqliteAccountInfoRow interface {
	sqlcsqlite.GetAccountByScopeAndNameRow |
		sqlcsqlite.GetAccountByScopeAndNumberRow |
		sqlcsqlite.GetAccountByWalletScopeAndNameRow |
		sqlcsqlite.GetAccountByWalletScopeAndNumberRow |
		sqlcsqlite.ListAccountsByWalletRow |
		sqlcsqlite.ListAccountsByWalletScopeRow |
		sqlcsqlite.ListAccountsByWalletAndNameRow
}

// sqliteAccountRowToInfo converts a SQLite account row to an AccountInfo
// struct. It uses type conversion since all sqliteAccountInfoRow types have
// identical fields.
func sqliteAccountRowToInfo[T sqliteAccountInfoRow](row T) (*db.AccountInfo,
	error) {

	// Direct conversion works only because all constraint types have
	// identical fields. If sqlc types diverge, compilation will fail.
	base := sqlcsqlite.GetAccountByScopeAndNameRow(row)

	return db.AccountRowToInfo(db.AccountInfoRow[int64]{
		AccountNumber:    base.AccountNumber,
		AccountName:      base.AccountName,
		OriginID:         base.OriginID,
		ExternalKeyCount: base.ExternalKeyCount,
		InternalKeyCount: base.InternalKeyCount,
		ImportedKeyCount: base.ImportedKeyCount,
		IsWatchOnly:      base.IsWatchOnly,
		CreatedAt:        base.CreatedAt,
		Purpose:          base.Purpose,
		CoinType:         base.CoinType,
		IDToOriginType:   db.IDToAccountOrigin[int64],
	})
}

// sqliteAccountListQueries groups SQLite account listing query methods.
type sqliteAccountListQueries struct {
	q *sqlcsqlite.Queries
}

// byScope lists accounts filtered by wallet ID and key scope.
func (s sqliteAccountListQueries) byScope(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	return db.ListAccounts(
		ctx, s.q.ListAccountsByWalletScope,
		sqlcsqlite.ListAccountsByWalletScopeParams{
			WalletID: int64(query.WalletID),
			Purpose:  int64(query.Scope.Purpose),
			CoinType: int64(query.Scope.Coin),
		}, sqliteAccountRowToInfo,
	)
}

// byName lists accounts filtered by wallet ID and account name.
func (s sqliteAccountListQueries) byName(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	return db.ListAccounts(
		ctx, s.q.ListAccountsByWalletAndName,
		sqlcsqlite.ListAccountsByWalletAndNameParams{
			WalletID:    int64(query.WalletID),
			AccountName: *query.Name,
		}, sqliteAccountRowToInfo,
	)
}

// all lists all accounts for a wallet.
func (s sqliteAccountListQueries) all(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	return db.ListAccounts(
		ctx, s.q.ListAccountsByWallet, int64(query.WalletID),
		sqliteAccountRowToInfo,
	)
}

// sqliteAccountGetQueries groups SQLite account retrieval query methods.
type sqliteAccountGetQueries struct {
	q *sqlcsqlite.Queries
}

// byNumber retrieves an account by wallet ID, scope, and account number.
func (s sqliteAccountGetQueries) byNumber(ctx context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	return db.GetAccount(
		ctx, s.q.GetAccountByWalletScopeAndNumber,
		sqlcsqlite.GetAccountByWalletScopeAndNumberParams{
			WalletID:      int64(query.WalletID),
			Purpose:       int64(query.Scope.Purpose),
			CoinType:      int64(query.Scope.Coin),
			AccountNumber: db.NullableUint32ToSQLInt64(query.AccountNumber),
		}, query, sqliteAccountRowToInfo,
	)
}

// byName retrieves an account by wallet ID, scope, and account name.
func (s sqliteAccountGetQueries) byName(ctx context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	return db.GetAccount(ctx, s.q.GetAccountByWalletScopeAndName,
		sqlcsqlite.GetAccountByWalletScopeAndNameParams{
			WalletID:    int64(query.WalletID),
			Purpose:     int64(query.Scope.Purpose),
			CoinType:    int64(query.Scope.Coin),
			AccountName: *query.Name,
		}, query, sqliteAccountRowToInfo,
	)
}

// sqliteAccountRenameQueries groups SQLite account rename query methods.
type sqliteAccountRenameQueries struct {
	q *sqlcsqlite.Queries
}

// byNumber renames an account identified by wallet ID, scope, and account
// number.
func (s sqliteAccountRenameQueries) byNumber(ctx context.Context,
	params db.RenameAccountParams) error {

	return db.RenameAccount(
		ctx, s.q.UpdateAccountNameByWalletScopeAndNumber,
		sqlcsqlite.UpdateAccountNameByWalletScopeAndNumberParams{
			NewName:       params.NewName,
			WalletID:      int64(params.WalletID),
			Purpose:       int64(params.Scope.Purpose),
			CoinType:      int64(params.Scope.Coin),
			AccountNumber: db.NullableUint32ToSQLInt64(params.AccountNumber),
		}, params,
	)
}

// byName renames an account identified by wallet ID, scope, and old account
// name.
func (s sqliteAccountRenameQueries) byName(ctx context.Context,
	params db.RenameAccountParams) error {

	return db.RenameAccount(
		ctx, s.q.UpdateAccountNameByWalletScopeAndName,
		sqlcsqlite.UpdateAccountNameByWalletScopeAndNameParams{
			NewName:  params.NewName,
			WalletID: int64(params.WalletID),
			Purpose:  int64(params.Scope.Purpose),
			CoinType: int64(params.Scope.Coin),
			OldName:  params.OldName,
		}, params,
	)
}
