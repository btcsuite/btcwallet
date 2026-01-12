package db

import (
	"context"
	"database/sql"
	"fmt"

	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// Ensure PostgresWalletDB satisfies the AccountStore interface.
var _ AccountStore = (*PostgresWalletDB)(nil)

// GetAccount retrieves information about a specific account, identified by its
// name or account number within a given key scope.
func (w *PostgresWalletDB) GetAccount(ctx context.Context,
	query GetAccountQuery) (*AccountInfo, error) {

	getQueries := pgAccountGetQueries{q: w.queries}

	return getAccountByQuery(ctx, query, getQueries.byNumber, getQueries.byName)
}

// ListAccounts returns a slice of AccountInfo for all accounts, optionally
// filtered by name or key scope.
func (w *PostgresWalletDB) ListAccounts(ctx context.Context,
	query ListAccountsQuery) ([]AccountInfo, error) {

	listQueries := pgAccountListQueries{q: w.queries}

	return listAccountsByQuery(
		ctx, query, listQueries.byScope, listQueries.byName, listQueries.all,
	)
}

// RenameAccount changes the name of an account. The account can be identified
// by its old name or its account number.
func (w *PostgresWalletDB) RenameAccount(ctx context.Context,
	params RenameAccountParams) error {

	renameQueries := pgAccountRenameQueries{q: w.queries}

	return renameAccountByQuery(
		ctx, params, renameQueries.byNumber, renameQueries.byName,
	)
}

// CreateDerivedAccount creates a new derived account with the given name and
// scope. If the key scope does not exist, it is created with NULL encrypted
// keys using the address schema provided by the caller.
func (w *PostgresWalletDB) CreateDerivedAccount(ctx context.Context,
	params CreateDerivedAccountParams) (*AccountInfo, error) {

	paramsErr := params.validate()
	if paramsErr != nil {
		return nil, paramsErr
	}

	var info *AccountInfo

	err := w.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		scopeID, err := pgEnsureKeyScope(
			ctx, qtx, params.WalletID, params.Scope,
		)
		if err != nil {
			return err
		}

		// Acquire an advisory lock for this scope to serialize account creation
		// and prevent race conditions when computing MAX(account_number). This
		// MUST be a separate statement that completes before
		// qtx.CreateDerivedAccount runs. See the LockAccountScope comments for
		// why single-statement approaches don't work.
		err = qtx.LockAccountScope(ctx, scopeID)
		if err != nil {
			return fmt.Errorf("lock account scope: %w", err)
		}

		row, err := qtx.CreateDerivedAccount(
			ctx, sqlcpg.CreateDerivedAccountParams{
				ScopeID:     scopeID,
				AccountName: params.Name,
				OriginID:    int16(DerivedAccount),
				IsWatchOnly: false,
			},
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
			accNumber, params.Name, DerivedAccount, 0, 0, 0, false,
			row.CreatedAt, params.Scope,
		)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// CreateImportedAccount stores an imported account identified by an extended
// public key. If the key scope does not exist, it is created with NULL
// encrypted keys using the address schema provided by the caller. Imported
// accounts have NULL account_number since they don't follow BIP44 derivation.
func (w *PostgresWalletDB) CreateImportedAccount(ctx context.Context,
	params CreateImportedAccountParams) (*AccountProperties, error) {

	var props *AccountProperties

	err := w.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		var err error

		props, err = createImportedAccount(
			ctx, params, func() (int64, error) {
				return pgEnsureKeyScope(ctx, qtx, params.WalletID, params.Scope)
			}, qtx.CreateImportedAccount,
			pgBuildCreateImportedAccountArgs(params),
			func(row sqlcpg.CreateImportedAccountRow) int64 { return row.ID },
			qtx.CreateAccountSecret, pgBuildCreateAccountSecretArgs(params),
			func(accountID int64) (*AccountProperties, error) {
				return pgGetAccountProps(ctx, qtx, accountID)
			},
		)

		return err
	})
	if err != nil {
		return nil, err
	}

	return props, nil
}

// pgBuildCreateImportedAccountArgs returns a function that builds the
// CreateImportedAccountParams for PostgreSQL.
func pgBuildCreateImportedAccountArgs(
	params CreateImportedAccountParams,
) func(int64, bool) sqlcpg.CreateImportedAccountParams {

	return func(scopeID int64,
		isWatchOnly bool) sqlcpg.CreateImportedAccountParams {

		return sqlcpg.CreateImportedAccountParams{
			ScopeID:            scopeID,
			AccountName:        params.Name,
			OriginID:           int16(ImportedAccount),
			EncryptedPublicKey: params.EncryptedPublicKey,
			MasterFingerprint: sql.NullInt64{
				Int64: int64(params.MasterFingerprint),
				Valid: true,
			},
			IsWatchOnly: isWatchOnly,
		}
	}
}

// pgBuildCreateAccountSecretArgs returns a function that builds the
// CreateAccountSecretParams for PostgreSQL.
func pgBuildCreateAccountSecretArgs(
	params CreateImportedAccountParams,
) func(int64) sqlcpg.CreateAccountSecretParams {

	return func(accountID int64) sqlcpg.CreateAccountSecretParams {
		return sqlcpg.CreateAccountSecretParams{
			AccountID:           accountID,
			EncryptedPrivateKey: params.EncryptedPrivateKey,
		}
	}
}

// pgGetAccountProps fetches full account properties from the database and
// converts the row to AccountProperties.
func pgGetAccountProps(ctx context.Context, qtx *sqlcpg.Queries,
	accountID int64) (*AccountProperties, error) {

	row, err := qtx.GetAccountPropsById(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("get account props: %w", err)
	}

	return accountPropsRowToProps(accountPropsRow[int16, int16]{
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
		IDToAddrType:       idToAddressType[int16],
		IDToOriginType:     idToAccountOrigin[int16],
	})
}

// pgEnsureKeyScope retrieves an existing key scope or creates it if missing for
// PostgreSQL. It returns the scope ID once available.
func pgEnsureKeyScope(ctx context.Context, qtx *sqlcpg.Queries, walletID uint32,
	scope KeyScope) (int64, error) {

	return ensureKeyScope(
		ctx, qtx.GetKeyScopeByWalletAndScope,
		sqlcpg.GetKeyScopeByWalletAndScopeParams{
			WalletID: int64(walletID),
			Purpose:  int64(scope.Purpose),
			CoinType: int64(scope.Coin),
		}, qtx.CreateKeyScope,
		func(addrSchema ScopeAddrSchema) sqlcpg.CreateKeyScopeParams {
			return sqlcpg.CreateKeyScopeParams{
				WalletID:            int64(walletID),
				Purpose:             int64(scope.Purpose),
				CoinType:            int64(scope.Coin),
				EncryptedCoinPubKey: nil,
				InternalTypeID: int16(
					addrSchema.InternalAddrType,
				),
				ExternalTypeID: int16(
					addrSchema.ExternalAddrType,
				),
			}
		},
		func(row sqlcpg.KeyScope) int64 {
			return row.ID
		}, scope,
	)
}

// pgAccountInfoRow is a type constraint for PostgreSQL account info row types
// that share the same field structure. This enables a single generic conversion
// function to handle all account query result types.
type pgAccountInfoRow interface {
	sqlcpg.GetAccountByScopeAndNameRow |
		sqlcpg.GetAccountByScopeAndNumberRow |
		sqlcpg.GetAccountByWalletScopeAndNameRow |
		sqlcpg.GetAccountByWalletScopeAndNumberRow |
		sqlcpg.ListAccountsByWalletRow |
		sqlcpg.ListAccountsByWalletScopeRow |
		sqlcpg.ListAccountsByWalletAndNameRow
}

// pgAccountRowToInfo converts a PostgreSQL account row to an AccountInfo
// struct. It uses type conversion since all pgAccountInfoRow types have
// identical fields.
func pgAccountRowToInfo[T pgAccountInfoRow](row T) (*AccountInfo, error) {
	// Direct conversion works only because all constraint types have
	// identical fields. If sqlc types diverge, compilation will fail.
	base := sqlcpg.GetAccountByScopeAndNameRow(row)

	return accountRowToInfo(accountInfoRow[int16]{
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
		IDToOriginType:   idToAccountOrigin[int16],
	})
}

// pgAccountListQueries groups PostgreSQL account listing query methods.
type pgAccountListQueries struct {
	q *sqlcpg.Queries
}

// byScope lists accounts filtered by wallet ID and key scope.
func (p pgAccountListQueries) byScope(ctx context.Context,
	query ListAccountsQuery) ([]AccountInfo, error) {

	return listAccounts(
		ctx, p.q.ListAccountsByWalletScope,
		sqlcpg.ListAccountsByWalletScopeParams{
			WalletID: int64(query.WalletID),
			Purpose:  int64(query.Scope.Purpose),
			CoinType: int64(query.Scope.Coin),
		}, pgAccountRowToInfo,
	)
}

// byName lists accounts filtered by wallet ID and account name.
func (p pgAccountListQueries) byName(ctx context.Context,
	query ListAccountsQuery) ([]AccountInfo, error) {

	return listAccounts(
		ctx, p.q.ListAccountsByWalletAndName,
		sqlcpg.ListAccountsByWalletAndNameParams{
			WalletID:    int64(query.WalletID),
			AccountName: *query.Name,
		}, pgAccountRowToInfo,
	)
}

// all lists all accounts for a wallet.
func (p pgAccountListQueries) all(ctx context.Context,
	query ListAccountsQuery) ([]AccountInfo, error) {

	return listAccounts(
		ctx, p.q.ListAccountsByWallet, int64(query.WalletID),
		pgAccountRowToInfo,
	)
}

// pgAccountGetQueries groups PostgreSQL account retrieval query methods.
type pgAccountGetQueries struct {
	q *sqlcpg.Queries
}

// byNumber retrieves an account by wallet ID, scope, and account number.
func (p pgAccountGetQueries) byNumber(ctx context.Context,
	query GetAccountQuery) (*AccountInfo, error) {

	return getAccount(
		ctx, p.q.GetAccountByWalletScopeAndNumber,
		sqlcpg.GetAccountByWalletScopeAndNumberParams{
			WalletID: int64(query.WalletID),
			Purpose:  int64(query.Scope.Purpose),
			CoinType: int64(query.Scope.Coin),
			AccountNumber: sql.NullInt64{
				Int64: int64(*query.AccountNumber),
				Valid: true,
			},
		}, query, pgAccountRowToInfo,
	)
}

// byName retrieves an account by wallet ID, scope, and account name.
func (p pgAccountGetQueries) byName(ctx context.Context,
	query GetAccountQuery) (*AccountInfo, error) {

	return getAccount(
		ctx, p.q.GetAccountByWalletScopeAndName,
		sqlcpg.GetAccountByWalletScopeAndNameParams{
			WalletID:    int64(query.WalletID),
			Purpose:     int64(query.Scope.Purpose),
			CoinType:    int64(query.Scope.Coin),
			AccountName: *query.Name,
		}, query, pgAccountRowToInfo,
	)
}

// pgAccountRenameQueries groups PostgreSQL account rename query methods.
type pgAccountRenameQueries struct {
	q *sqlcpg.Queries
}

// byNumber renames an account identified by wallet ID, scope, and account
// number.
func (p pgAccountRenameQueries) byNumber(ctx context.Context,
	params RenameAccountParams) error {

	return renameAccount(
		ctx, p.q.UpdateAccountNameByWalletScopeAndNumber,
		sqlcpg.UpdateAccountNameByWalletScopeAndNumberParams{
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
func (p pgAccountRenameQueries) byName(ctx context.Context,
	params RenameAccountParams) error {

	return renameAccount(
		ctx, p.q.UpdateAccountNameByWalletScopeAndName,
		sqlcpg.UpdateAccountNameByWalletScopeAndNameParams{
			NewName:  params.NewName,
			WalletID: int64(params.WalletID),
			Purpose:  int64(params.Scope.Purpose),
			CoinType: int64(params.Scope.Coin),
			OldName:  params.OldName,
		}, params,
	)
}
