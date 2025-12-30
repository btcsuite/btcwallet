package db

import (
	"context"
	"database/sql"
	"fmt"

	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// Ensure SQLiteWalletDB satisfies the AccountStore interface.
var _ AccountStore = (*SQLiteWalletDB)(nil)

// GetAccount retrieves information about a specific account, identified by its
// name or account number within a given key scope.
func (w *SQLiteWalletDB) GetAccount(ctx context.Context,
	query GetAccountQuery) (*AccountInfo, error) {

	getQueries := sqliteAccountGetQueries{q: w.queries}

	return getAccountByQuery(ctx, query, getQueries.byNumber, getQueries.byName)
}

// ListAccounts returns a slice of AccountInfo for all accounts, optionally
// filtered by name or key scope.
func (w *SQLiteWalletDB) ListAccounts(ctx context.Context,
	query ListAccountsQuery) ([]AccountInfo, error) {

	listQueries := sqliteAccountListQueries{q: w.queries}

	return listAccountsByQuery(
		ctx, query, listQueries.byScope, listQueries.byName, listQueries.all,
	)
}

// RenameAccount changes the name of an account. The account can be identified
// by its old name or its account number.
func (w *SQLiteWalletDB) RenameAccount(ctx context.Context,
	params RenameAccountParams) error {

	renameQueries := sqliteAccountRenameQueries{q: w.queries}

	return renameAccountByQuery(
		ctx, params, renameQueries.byNumber, renameQueries.byName,
	)
}

// CreateDerivedAccount creates a new derived account with the given name and
// scope. If the key scope does not exist, it is created with NULL encrypted
// keys using the address schema provided by the caller.
func (w *SQLiteWalletDB) CreateDerivedAccount(ctx context.Context,
	params CreateDerivedAccountParams) (*AccountInfo, error) {

	paramsErr := params.validate()
	if paramsErr != nil {
		return nil, paramsErr
	}

	var info *AccountInfo

	err := w.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		scopeID, err := sqliteEnsureKeyScope(
			ctx, qtx, params.WalletID, params.Scope,
		)
		if err != nil {
			return err
		}

		row, err := sqliteAllocateAndCreateAccount(
			ctx, qtx, scopeID, params.Name,
		)
		if err != nil {
			return fmt.Errorf("create account: %w", err)
		}

		if !row.AccountNumber.Valid {
			// This should never happen unless the query is modified
			// incorrectly.
			return errNilDBAccountNumber
		}

		accNumber, err := int64ToUint32(row.AccountNumber.Int64)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrMaxAccountNumberReached, err)
		}

		info = buildAccountInfo(
			accNumber, params.Name, DerivedAccount, false,
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
	walletID uint32, scope KeyScope) (int64, error) {

	return ensureKeyScope(
		ctx, qtx.GetKeyScopeByWalletAndScope,
		sqlcsqlite.GetKeyScopeByWalletAndScopeParams{
			WalletID: int64(walletID),
			Purpose:  int64(scope.Purpose),
			CoinType: int64(scope.Coin),
		}, qtx.CreateKeyScope,
		func(addrSchema ScopeAddrSchema) sqlcsqlite.CreateKeyScopeParams {
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
		func(row sqlcsqlite.GetKeyScopeByWalletAndScopeRow) int64 {
			return row.ID
		}, scope,
	)
}

// sqliteAllocateAndCreateAccount allocates a new sequential account number and
// creates a derived account in a single atomic operation. SQLite requires a
// two-step process because it lacks PostgreSQL's UPDATE ... RETURNING clause.
func sqliteAllocateAndCreateAccount(ctx context.Context,
	qtx *sqlcsqlite.Queries, scopeID int64,
	accountName string) (sqlcsqlite.CreateDerivedAccountRow, error) {

	allocated, err := qtx.AllocateAccountNumber(ctx, scopeID)
	if err != nil {
		return sqlcsqlite.CreateDerivedAccountRow{},
			fmt.Errorf("allocate account number: %w", err)
	}

	row, err := qtx.CreateDerivedAccount(ctx,
		sqlcsqlite.CreateDerivedAccountParams{
			ScopeID: scopeID,
			AccountNumber: sql.NullInt64{
				Int64: allocated.LastAccountNumber,
				Valid: true,
			},
			AccountName: accountName,
			OriginID:    int64(DerivedAccount),
			IsWatchOnly: false,
		})
	if err != nil {
		return sqlcsqlite.CreateDerivedAccountRow{},
			fmt.Errorf("create account: %w", err)
	}

	return row, nil
}

// CreateImportedAccount stores an imported account identified by an extended
// public key. If the key scope does not exist, it is created with NULL
// encrypted keys using the address schema provided by the caller. Imported
// accounts have NULL account_number since they don't follow BIP44 derivation.
func (w *SQLiteWalletDB) CreateImportedAccount(ctx context.Context,
	params CreateImportedAccountParams) (*AccountProperties, error) {

	var props *AccountProperties

	err := w.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		var err error

		props, err = createImportedAccount(
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
			func(accountID int64) (*AccountProperties, error) {
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
	params CreateImportedAccountParams,
) func(int64, bool) sqlcsqlite.CreateImportedAccountParams {

	return func(scopeID int64,
		isWatchOnly bool) sqlcsqlite.CreateImportedAccountParams {

		return sqlcsqlite.CreateImportedAccountParams{
			ScopeID:            scopeID,
			AccountName:        params.Name,
			OriginID:           int64(ImportedAccount),
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
	params CreateImportedAccountParams,
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
	accountID int64) (*AccountProperties, error) {

	row, err := qtx.GetAccountPropsById(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("get account props: %w", err)
	}

	return accountPropsRowToProps(accountPropsRow[int64, int64]{
		AccountNumber:      row.AccountNumber,
		AccountName:        row.AccountName,
		OriginID:           row.OriginID,
		EncryptedPublicKey: row.EncryptedPublicKey,
		MasterFingerprint:  row.MasterFingerprint,
		IsWatchOnly:        row.IsWatchOnly,
		CreatedAt:          row.CreatedAt,
		Purpose:            row.Purpose,
		CoinType:           row.CoinType,
		InternalTypeID:     row.InternalTypeID,
		ExternalTypeID:     row.ExternalTypeID,
		IDToAddrType:       idToAddressType[int64],
		IDToOriginType:     idToAccountOrigin[int64],
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
func sqliteAccountRowToInfo[T sqliteAccountInfoRow](row T) (*AccountInfo,
	error) {

	// Direct conversion works only because all constraint types have
	// identical fields. If sqlc types diverge, compilation will fail.
	base := sqlcsqlite.GetAccountByScopeAndNameRow(row)

	return accountRowToInfo(accountInfoRow[int64]{
		AccountNumber:  base.AccountNumber,
		AccountName:    base.AccountName,
		OriginID:       base.OriginID,
		IsWatchOnly:    base.IsWatchOnly,
		CreatedAt:      base.CreatedAt,
		Purpose:        base.Purpose,
		CoinType:       base.CoinType,
		IDToOriginType: idToAccountOrigin[int64],
	})
}

// sqliteAccountListQueries groups SQLite account listing query methods.
type sqliteAccountListQueries struct {
	q *sqlcsqlite.Queries
}

// byScope lists accounts filtered by wallet ID and key scope.
func (s sqliteAccountListQueries) byScope(ctx context.Context,
	query ListAccountsQuery) ([]AccountInfo, error) {

	return listAccounts(
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
	query ListAccountsQuery) ([]AccountInfo, error) {

	return listAccounts(
		ctx, s.q.ListAccountsByWalletAndName,
		sqlcsqlite.ListAccountsByWalletAndNameParams{
			WalletID:    int64(query.WalletID),
			AccountName: *query.Name,
		}, sqliteAccountRowToInfo,
	)
}

// all lists all accounts for a wallet.
func (s sqliteAccountListQueries) all(ctx context.Context,
	query ListAccountsQuery) ([]AccountInfo, error) {

	return listAccounts(
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
	query GetAccountQuery) (*AccountInfo, error) {

	return getAccount(
		ctx, s.q.GetAccountByWalletScopeAndNumber,
		sqlcsqlite.GetAccountByWalletScopeAndNumberParams{
			WalletID: int64(query.WalletID),
			Purpose:  int64(query.Scope.Purpose),
			CoinType: int64(query.Scope.Coin),
			AccountNumber: sql.NullInt64{
				Int64: int64(*query.AccountNumber),
				Valid: true,
			},
		}, query, sqliteAccountRowToInfo,
	)
}

// byName retrieves an account by wallet ID, scope, and account name.
func (s sqliteAccountGetQueries) byName(ctx context.Context,
	query GetAccountQuery) (*AccountInfo, error) {

	return getAccount(ctx, s.q.GetAccountByWalletScopeAndName,
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
	params RenameAccountParams) error {

	return renameAccount(
		ctx, s.q.UpdateAccountNameByWalletScopeAndNumber,
		sqlcsqlite.UpdateAccountNameByWalletScopeAndNumberParams{
			NewName:  params.NewName,
			WalletID: int64(params.WalletID),
			Purpose:  int64(params.Scope.Purpose),
			CoinType: int64(params.Scope.Coin),
			AccountNumber: sql.NullInt64{
				Int64: int64(*params.AccountNumber),
				Valid: true,
			},
		}, params,
	)
}

// byName renames an account identified by wallet ID, scope, and old account
// name.
func (s sqliteAccountRenameQueries) byName(ctx context.Context,
	params RenameAccountParams) error {

	return renameAccount(
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
