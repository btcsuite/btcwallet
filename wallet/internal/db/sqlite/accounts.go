package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// Ensure Store satisfies the AccountStore interface.
var _ db.AccountStore = (*Store)(nil)

// GetAccount retrieves information about a specific account, identified by its
// name or account number within a given key scope.
func (s *Store) GetAccount(ctx context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	var account *db.AccountInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		getQueries := accountGetQueries{q: q}

		var err error

		account, err = db.GetAccountByQuery(
			ctx, query, getQueries.byNumber, getQueries.byName,
		)

		return err
	})
	if err != nil {
		return nil, err
	}

	return account, nil
}

// ListAccounts returns a slice of AccountInfo for all accounts, optionally
// filtered by name or key scope.
func (s *Store) ListAccounts(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	var accounts []db.AccountInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		listQueries := accountListQueries{q: q}

		var err error

		accounts, err = db.ListAccountsByQuery(
			ctx, query, listQueries.byScope, listQueries.byName,
			listQueries.all,
		)

		return err
	})
	if err != nil {
		return nil, err
	}

	return accounts, nil
}

// RenameAccount changes the name of an account. The account can be identified
// by its old name or its account number.
func (s *Store) RenameAccount(ctx context.Context,
	params db.RenameAccountParams) error {

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		renameQueries := accountRenameQueries{q: qtx}

		return db.RenameAccountByQuery(
			ctx, params, renameQueries.byNumber, renameQueries.byName,
		)
	})
}

// CreateDerivedAccount creates a new derived account with the given name
// and scope. The wallet-supplied deriveFn callback is wired through the
// AccountStore interface; the shared workflow consumes it in a follow-up
// commit. If the key scope does not exist, it is created using the
// address schema provided by the caller with no coin public/private key
// material.
func (s *Store) CreateDerivedAccount(ctx context.Context,
	params db.CreateDerivedAccountParams,
	_ db.AccountDerivationFunc) (*db.AccountInfo, error) {

	var info *db.AccountInfo

	err := s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		var err error

		info, err = db.CreateDerivedAccountWithOps(
			ctx, params, createDerivedAccountOps{q: qtx},
		)

		return err
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// createDerivedAccountOps adapts SQLite sqlc queries to the shared
// CreateDerivedAccount workflow.
type createDerivedAccountOps struct {
	q *sqlc.Queries
}

// WalletWatchOnly implements db.CreateDerivedAccountOps.
func (o createDerivedAccountOps) WalletWatchOnly(ctx context.Context,
	walletID uint32) (bool, error) {

	return getWalletWatchOnly(ctx, o.q, walletID)
}

// EnsureScope implements db.CreateDerivedAccountOps.
func (o createDerivedAccountOps) EnsureScope(ctx context.Context,
	walletID uint32, scope db.KeyScope) (int64, error) {

	return ensureKeyScope(ctx, o.q, walletID, scope)
}

// AllocateAccountNumber implements db.CreateDerivedAccountOps.
func (o createDerivedAccountOps) AllocateAccountNumber(ctx context.Context,
	scopeID int64) (int64, error) {

	return o.q.GetAndIncrementNextAccountNumber(ctx, scopeID)
}

// CreateDerivedAccount implements db.CreateDerivedAccountOps.
func (o createDerivedAccountOps) CreateDerivedAccount(ctx context.Context,
	scopeID int64, accountNumber int64,
	name string) (db.CreateDerivedAccountRow, error) {

	row, err := o.q.CreateDerivedAccount(
		ctx, sqlc.CreateDerivedAccountParams{
			ScopeID: scopeID,
			AccountNumber: sql.NullInt64{
				Int64: accountNumber,
				Valid: true,
			},
			AccountName: name,
			OriginID:    int64(db.DerivedAccount),
		},
	)
	if err != nil {
		return db.CreateDerivedAccountRow{}, err
	}

	return db.CreateDerivedAccountRow{
		AccountNumber: row.AccountNumber,
		CreatedAt:     row.CreatedAt,
	}, nil
}

// ensureKeyScope retrieves an existing key scope or creates it if missing
// for SQLite. It returns the scope ID once available.
func ensureKeyScope(ctx context.Context, qtx *sqlc.Queries,
	walletID uint32, scope db.KeyScope) (int64, error) {

	return db.EnsureKeyScope(
		ctx, qtx.GetKeyScopeByWalletAndScope,
		sqlc.GetKeyScopeByWalletAndScopeParams{
			WalletID: int64(walletID),
			Purpose:  int64(scope.Purpose),
			CoinType: int64(scope.Coin),
		}, qtx.CreateKeyScope,
		func(addrSchema db.ScopeAddrSchema) sqlc.CreateKeyScopeParams {
			return sqlc.CreateKeyScopeParams{
				WalletID:   int64(walletID),
				Purpose:    int64(scope.Purpose),
				CoinType:   int64(scope.Coin),
				CoinPubKey: nil,
				InternalTypeID: int64(
					addrSchema.InternalAddrType,
				),
				ExternalTypeID: int64(
					addrSchema.ExternalAddrType,
				),
			}
		},
		func(row sqlc.GetKeyScopeByWalletAndScopeRow) int64 {
			return row.ID
		}, scope,
	)
}

// CreateImportedAccount stores an imported account identified by an extended
// public key. If the key scope does not exist, it is created using the address
// schema provided by the caller with no coin public/private key material.
// Imported accounts have NULL account_number since they don't follow BIP44
// derivation.
func (s *Store) CreateImportedAccount(ctx context.Context,
	params db.CreateImportedAccountParams) (*db.AccountInfo, error) {

	var props *db.AccountInfo

	err := s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		var err error

		props, err = db.CreateImportedAccount(
			ctx, params,
			func() (int64, error) {
				return ensureKeyScope(
					ctx, qtx, params.WalletID, params.Scope,
				)
			},
			func() (bool, error) {
				return getWalletWatchOnly(ctx, qtx, params.WalletID)
			},
			qtx.CreateImportedAccount,
			buildCreateImportedAccountArgs(params),
			func(row sqlc.CreateImportedAccountRow) int64 {
				return row.ID
			},
			qtx.CreateAccountSecret, buildCreateAccountSecretArgs(params),
			func(accountID int64) (*db.AccountInfo, error) {
				return getAccountProps(ctx, qtx, accountID)
			},
		)

		return err
	})
	if err != nil {
		return nil, err
	}

	return props, nil
}

// getWalletWatchOnly returns the current watch-only mode for the wallet.
func getWalletWatchOnly(ctx context.Context, qtx *sqlc.Queries,
	walletID uint32) (bool, error) {

	row, err := qtx.GetWalletByID(ctx, int64(walletID))
	if err == nil {
		return row.IsWatchOnly, nil
	}

	if errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("wallet %d: %w", walletID,
			db.ErrWalletNotFound)
	}

	return false, fmt.Errorf("get wallet: %w", err)
}

// buildCreateImportedAccountArgs returns a function that builds the
// CreateImportedAccountParams for SQLite.
func buildCreateImportedAccountArgs(
	params db.CreateImportedAccountParams,
) func(int64) sqlc.CreateImportedAccountParams {

	return func(scopeID int64) sqlc.CreateImportedAccountParams {
		return sqlc.CreateImportedAccountParams{
			ScopeID:     scopeID,
			AccountName: params.Name,
			OriginID:    int64(db.ImportedAccount),
			PublicKey:   params.PublicKey,
			MasterFingerprint: sql.NullInt64{
				Int64: int64(params.MasterFingerprint),
				Valid: true,
			},
		}
	}
}

// buildCreateAccountSecretArgs returns a function that builds the
// CreateAccountSecretParams for SQLite.
func buildCreateAccountSecretArgs(
	params db.CreateImportedAccountParams,
) func(int64) sqlc.CreateAccountSecretParams {

	return func(accountID int64) sqlc.CreateAccountSecretParams {
		return sqlc.CreateAccountSecretParams{
			AccountID: accountID,
			EncryptedPrivateKey: db.NilIfEmptyBytes(
				params.EncryptedPrivateKey,
			),
		}
	}
}

// getAccountProps fetches full account properties from the database and
// converts the row to AccountInfo.
func getAccountProps(ctx context.Context, qtx *sqlc.Queries,
	accountID int64) (*db.AccountInfo, error) {

	row, err := qtx.GetAccountPropsById(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("get account props: %w", err)
	}

	return db.AccountPropsRowToInfo(db.AccountPropsRow[int64, int64]{
		AccountNumber:     row.AccountNumber,
		AccountName:       row.AccountName,
		OriginID:          row.OriginID,
		ExternalKeyCount:  row.ExternalKeyCount,
		InternalKeyCount:  row.InternalKeyCount,
		ImportedKeyCount:  row.ImportedKeyCount,
		PublicKey:         row.PublicKey,
		MasterFingerprint: row.MasterFingerprint,
		IsWatchOnly:       row.IsWatchOnly,
		CreatedAt:         row.CreatedAt,
		Purpose:           row.Purpose,
		CoinType:          row.CoinType,
		IDToOriginType:    db.IDToAccountOrigin[int64],
	})
}

// accountInfoRow is a type constraint for SQLite account info row types
// that share the same field structure. This enables a single generic conversion
// function to handle all account query result types.
type accountInfoRow interface {
	sqlc.GetAccountByScopeAndNameRow |
		sqlc.GetAccountByScopeAndNumberRow |
		sqlc.GetAccountByWalletScopeAndNameRow |
		sqlc.GetAccountByWalletScopeAndNumberRow |
		sqlc.ListAccountsByWalletRow |
		sqlc.ListAccountsByWalletScopeRow |
		sqlc.ListAccountsByWalletAndNameRow
}

// derivedAddressGetAccountID extracts the account ID from a row.
func derivedAddressGetAccountID(
	row sqlc.GetAccountByWalletScopeAndNameRow) int64 {

	return row.ID
}

// derivedAddressGetWalletWatchOnly extracts the wallet-level watch-only state
// from a row.
func derivedAddressGetWalletWatchOnly(
	row sqlc.GetAccountByWalletScopeAndNameRow) bool {

	return row.WalletIsWatchOnly
}

// importedAddressGetAccountID extracts the account ID from a row.
func importedAddressGetAccountID(
	row sqlc.GetAccountByWalletScopeAndNameRow) int64 {

	return row.ID
}

// importedAddressGetWalletWatchOnly extracts the wallet-level watch-only state
// from a row.
func importedAddressGetWalletWatchOnly(
	row sqlc.GetAccountByWalletScopeAndNameRow) bool {

	return row.WalletIsWatchOnly
}

// accountRowToInfo converts a SQLite account row to an AccountInfo
// struct. It uses type conversion since all accountInfoRow types have
// identical fields.
func accountRowToInfo[T accountInfoRow](row T) (*db.AccountInfo,
	error) {

	// Direct conversion works only because all constraint types have
	// identical fields. If sqlc types diverge, compilation will fail.
	base := sqlc.GetAccountByScopeAndNameRow(row)

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

// accountListQueries groups SQLite account listing query methods.
type accountListQueries struct {
	q *sqlc.Queries
}

// byScope lists accounts filtered by wallet ID and key scope.
func (s accountListQueries) byScope(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	return db.ListAccounts(
		ctx, s.q.ListAccountsByWalletScope,
		sqlc.ListAccountsByWalletScopeParams{
			WalletID: int64(query.WalletID),
			Purpose:  int64(query.Scope.Purpose),
			CoinType: int64(query.Scope.Coin),
		}, accountRowToInfo,
	)
}

// byName lists accounts filtered by wallet ID and account name.
func (s accountListQueries) byName(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	return db.ListAccounts(
		ctx, s.q.ListAccountsByWalletAndName,
		sqlc.ListAccountsByWalletAndNameParams{
			WalletID:    int64(query.WalletID),
			AccountName: *query.Name,
		}, accountRowToInfo,
	)
}

// all lists all accounts for a wallet.
func (s accountListQueries) all(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	return db.ListAccounts(
		ctx, s.q.ListAccountsByWallet, int64(query.WalletID),
		accountRowToInfo,
	)
}

// accountGetQueries groups SQLite account retrieval query methods.
type accountGetQueries struct {
	q *sqlc.Queries
}

// byNumber retrieves an account by wallet ID, scope, and account number.
func (s accountGetQueries) byNumber(ctx context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	return db.GetAccount(
		ctx, s.q.GetAccountByWalletScopeAndNumber,
		sqlc.GetAccountByWalletScopeAndNumberParams{
			WalletID:      int64(query.WalletID),
			Purpose:       int64(query.Scope.Purpose),
			CoinType:      int64(query.Scope.Coin),
			AccountNumber: db.NullableUint32ToSQLInt64(query.AccountNumber),
		}, query, accountRowToInfo,
	)
}

// byName retrieves an account by wallet ID, scope, and account name.
func (s accountGetQueries) byName(ctx context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	return db.GetAccount(ctx, s.q.GetAccountByWalletScopeAndName,
		sqlc.GetAccountByWalletScopeAndNameParams{
			WalletID:    int64(query.WalletID),
			Purpose:     int64(query.Scope.Purpose),
			CoinType:    int64(query.Scope.Coin),
			AccountName: *query.Name,
		}, query, accountRowToInfo,
	)
}

// accountRenameQueries groups SQLite account rename query methods.
type accountRenameQueries struct {
	q *sqlc.Queries
}

// byNumber renames an account identified by wallet ID, scope, and account
// number.
func (s accountRenameQueries) byNumber(ctx context.Context,
	params db.RenameAccountParams) error {

	return db.RenameAccount(
		ctx, s.q.UpdateAccountNameByWalletScopeAndNumber,
		sqlc.UpdateAccountNameByWalletScopeAndNumberParams{
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
func (s accountRenameQueries) byName(ctx context.Context,
	params db.RenameAccountParams) error {

	return db.RenameAccount(
		ctx, s.q.UpdateAccountNameByWalletScopeAndName,
		sqlc.UpdateAccountNameByWalletScopeAndNameParams{
			NewName:  params.NewName,
			WalletID: int64(params.WalletID),
			Purpose:  int64(params.Scope.Purpose),
			CoinType: int64(params.Scope.Coin),
			OldName:  params.OldName,
		}, params,
	)
}
