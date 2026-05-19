package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// Ensure Store satisfies the AccountStore interface.
var _ db.AccountStore = (*Store)(nil)

var errDryRunRollback = errors.New("postgres imported account dry run rollback")

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

// CreateDerivedAccount creates a new derived account with the given name and
// scope. After allocating the account number, the wallet-supplied deriveFn
// callback returns the account material (extended public key, encrypted
// private key, master-key fingerprint, optional address schema) which is
// persisted together with the row. If the key scope does not exist, it is
// created with NULL public/private key fields using the address schema
// provided by the caller.
func (s *Store) CreateDerivedAccount(ctx context.Context,
	params db.CreateDerivedAccountParams,
	deriveFn db.AccountDerivationFunc) (*db.AccountInfo, error) {

	var info *db.AccountInfo

	err := s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		var err error

		info, err = db.CreateDerivedAccountWithOps(
			ctx, params, createDerivedAccountOps{q: qtx}, deriveFn,
		)

		return err
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}

// createDerivedAccountOps adapts PostgreSQL sqlc queries to the shared
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

	return ensureKeyScope(ctx, o.q, walletID, scope, nil)
}

// AllocateAccountNumber implements db.CreateDerivedAccountOps.
func (o createDerivedAccountOps) AllocateAccountNumber(ctx context.Context,
	scopeID int64) (int64, error) {

	return o.q.GetAndIncrementNextAccountNumber(ctx, scopeID)
}

// CreateDerivedAccount implements db.CreateDerivedAccountOps. The shared
// CreateDerivedAccountWithOps workflow validates derived before invoking
// this method, so derived must be non-nil; defensively reject anyway in
// case a future caller skips that validation.
func (o createDerivedAccountOps) CreateDerivedAccount(ctx context.Context,
	scopeID int64, accountNumber int64, name string,
	derived *db.DerivedAccountData) (db.CreateDerivedAccountRow, error) {

	if derived == nil {
		return db.CreateDerivedAccountRow{}, db.ErrNilDerivedAccountData
	}

	row, err := o.q.CreateDerivedAccount(
		ctx, sqlc.CreateDerivedAccountParams{
			ScopeID: scopeID,
			AccountNumber: sql.NullInt64{
				Int64: accountNumber,
				Valid: true,
			},
			AccountName: name,
			OriginID:    int16(db.DerivedAccount),
			PublicKey:   derived.PublicKey,
			MasterFingerprint: sql.NullInt64{
				Int64: int64(derived.MasterKeyFingerprint),
				Valid: true,
			},
		},
	)
	if err != nil {
		return db.CreateDerivedAccountRow{}, err
	}

	if len(derived.EncryptedPrivateKey) > 0 {
		err = o.q.CreateAccountSecret(
			ctx, sqlc.CreateAccountSecretParams{
				AccountID:           row.ID,
				EncryptedPrivateKey: derived.EncryptedPrivateKey,
			},
		)
		if err != nil {
			return db.CreateDerivedAccountRow{},
				fmt.Errorf("create account secret: %w", err)
		}
	}

	return db.CreateDerivedAccountRow{
		AccountNumber: row.AccountNumber,
		CreatedAt:     row.CreatedAt,
	}, nil
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
			ctx, params, func() (int64, error) {
				return ensureKeyScope(
					ctx, qtx, params.WalletID, params.Scope,
					params.AddrSchema,
				)
			}, func() (bool, error) {
				return getWalletWatchOnly(ctx, qtx, params.WalletID)
			}, qtx.CreateImportedAccount,
			buildCreateImportedAccountArgs(params),
			func(row sqlc.CreateImportedAccountRow) int64 { return row.ID },
			qtx.CreateAccountSecret, buildCreateAccountSecretArgs(params),
			func(accountID int64) (*db.AccountInfo, error) {
				return getAccountProps(ctx, qtx, accountID)
			},
		)
		if err != nil {
			return err
		}

		if params.DryRun {
			// TODO: Reuse the SQL address-derivation helpers to match
			// kvdb/legacy dry-run by deriving sample external and
			// internal addresses before rolling this tx back. Account
			// import needs a derivation callback before it can call
			// those helpers.
			return errDryRunRollback
		}

		return nil
	})
	if err != nil {
		if params.DryRun && errors.Is(err, errDryRunRollback) {
			return props, nil
		}

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
// CreateImportedAccountParams for PostgreSQL.
func buildCreateImportedAccountArgs(
	params db.CreateImportedAccountParams,
) func(int64) sqlc.CreateImportedAccountParams {

	return func(scopeID int64) sqlc.CreateImportedAccountParams {
		return sqlc.CreateImportedAccountParams{
			ScopeID:     scopeID,
			AccountName: params.Name,
			OriginID:    int16(db.ImportedAccount),
			PublicKey:   params.PublicKey,
			MasterFingerprint: sql.NullInt64{
				Int64: int64(params.MasterFingerprint),
				Valid: true,
			},
		}
	}
}

// buildCreateAccountSecretArgs returns a function that builds the
// CreateAccountSecretParams for PostgreSQL.
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

	return db.AccountPropsRowToInfo(
		db.AccountPropsRow[int16, int16]{
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
			IDToOriginType:    db.IDToAccountOrigin[int16],
		},
	)
}

// ensureKeyScope retrieves an existing key scope or creates it if missing for
// PostgreSQL. It returns the scope ID once available.
func ensureKeyScope(ctx context.Context, qtx *sqlc.Queries, walletID uint32,
	scope db.KeyScope, addrSchema *db.ScopeAddrSchema) (int64, error) {

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
				InternalTypeID: int16(
					addrSchema.InternalAddrType,
				),
				ExternalTypeID: int16(
					addrSchema.ExternalAddrType,
				),
			}
		},
		func(row sqlc.GetKeyScopeByWalletAndScopeRow) int64 {
			return row.ID
		}, scope, addrSchema,
	)
}

// accountInfoRow is a type constraint for PostgreSQL account info row types
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

// accountRowToInfo converts a PostgreSQL account row to an AccountInfo
// struct. It uses type conversion since all accountInfoRow types have
// identical fields.
func accountRowToInfo[T accountInfoRow](row T) (*db.AccountInfo, error) {
	// Direct conversion works only because all constraint types have
	// identical fields. If sqlc types diverge, compilation will fail.
	base := sqlc.GetAccountByScopeAndNameRow(row)

	return db.AccountRowToInfo(
		db.AccountInfoRow[int16]{
			AccountNumber:     base.AccountNumber,
			AccountName:       base.AccountName,
			OriginID:          base.OriginID,
			ExternalKeyCount:  base.ExternalKeyCount,
			InternalKeyCount:  base.InternalKeyCount,
			ImportedKeyCount:  base.ImportedKeyCount,
			PublicKey:         base.PublicKey,
			MasterFingerprint: base.MasterFingerprint,
			IsWatchOnly:       base.IsWatchOnly,
			CreatedAt:         base.CreatedAt,
			Purpose:           base.Purpose,
			CoinType:          base.CoinType,
			IDToOriginType:    db.IDToAccountOrigin[int16],
		},
	)
}

// accountListQueries groups PostgreSQL account listing query methods.
type accountListQueries struct {
	q *sqlc.Queries
}

// byScope lists accounts filtered by wallet ID and key scope, then
// attaches each account's balance via AccountBalancesByIDs unless
// query.SkipBalance is set.
func (p accountListQueries) byScope(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	rows, err := p.q.ListAccountsByWalletScope(
		ctx, sqlc.ListAccountsByWalletScopeParams{
			WalletID: int64(query.WalletID),
			Purpose:  int64(query.Scope.Purpose),
			CoinType: int64(query.Scope.Coin),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}

	infos, err := db.ProcessAccountRows(
		rows,
		func(r sqlc.ListAccountsByWalletScopeRow) (*db.AccountInfo, int64,
			error) {

			info, err := accountRowToInfo(r)
			return info, r.ID, err
		},
	)
	if err != nil {
		return nil, err
	}

	return p.attachBalances(ctx, query, infos)
}

// byName lists accounts filtered by wallet ID and account name, then
// attaches each account's balance via AccountBalancesByIDs unless
// query.SkipBalance is set.
func (p accountListQueries) byName(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	rows, err := p.q.ListAccountsByWalletAndName(
		ctx, sqlc.ListAccountsByWalletAndNameParams{
			WalletID:    int64(query.WalletID),
			AccountName: *query.Name,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}

	infos, err := db.ProcessAccountRows(
		rows,
		func(r sqlc.ListAccountsByWalletAndNameRow) (*db.AccountInfo, int64,
			error) {

			info, err := accountRowToInfo(r)
			return info, r.ID, err
		},
	)
	if err != nil {
		return nil, err
	}

	return p.attachBalances(ctx, query, infos)
}

// all lists every account for a wallet, then attaches each account's
// balance via AccountBalancesByIDs unless query.SkipBalance is set.
func (p accountListQueries) all(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	rows, err := p.q.ListAccountsByWallet(ctx, int64(query.WalletID))
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}

	infos, err := db.ProcessAccountRows(
		rows,
		func(r sqlc.ListAccountsByWalletRow) (*db.AccountInfo, int64,
			error) {

			info, err := accountRowToInfo(r)
			return info, r.ID, err
		},
	)
	if err != nil {
		return nil, err
	}

	return p.attachBalances(ctx, query, infos)
}

// attachBalances forwards to db.AttachBalances with a backend-specific
// closure that runs AccountBalancesByIDs and converts the sqlc rows into
// the dialect-agnostic db.AccountBalance shape.
func (p accountListQueries) attachBalances(ctx context.Context,
	query db.ListAccountsQuery,
	infos []*db.AccountInfo) ([]db.AccountInfo, error) {

	return db.AttachBalances(
		ctx, query.WalletID, query.SkipBalance, infos,
		func(ctx context.Context, walletID uint32,
			ids []int64) ([]db.AccountBalance, error) {

			rows, err := p.q.AccountBalancesByIDs(
				ctx, sqlc.AccountBalancesByIDsParams{
					WalletID:   int64(walletID),
					AccountIds: ids,
				},
			)
			if err != nil {
				return nil, err
			}

			balances := make([]db.AccountBalance, len(rows))
			for i := range rows {
				balances[i] = db.AccountBalance{
					AccountID:   rows[i].AccountID,
					Confirmed:   rows[i].ConfirmedBalance,
					Unconfirmed: rows[i].UnconfirmedBalance,
				}
			}

			return balances, nil
		},
	)
}

// accountGetQueries groups PostgreSQL account retrieval query methods.
type accountGetQueries struct {
	q *sqlc.Queries
}

// byNumber retrieves an account by wallet ID, scope, and account number,
// then attaches its balance via AccountBalance unless query.SkipBalance
// is set.
func (p accountGetQueries) byNumber(ctx context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	row, err := p.q.GetAccountByWalletScopeAndNumber(
		ctx, sqlc.GetAccountByWalletScopeAndNumberParams{
			WalletID:      int64(query.WalletID),
			Purpose:       int64(query.Scope.Purpose),
			CoinType:      int64(query.Scope.Coin),
			AccountNumber: db.NullableUint32ToSQLInt64(query.AccountNumber),
		},
	)
	if err != nil {
		return nil, mapGetAccountErr(err, query)
	}

	info, err := accountRowToInfo(row)
	if err != nil {
		return nil, err
	}

	return p.attachBalance(ctx, query, info, row.ID)
}

// byName retrieves an account by wallet ID, scope, and account name, then
// attaches its balance via AccountBalance unless query.SkipBalance is set.
func (p accountGetQueries) byName(ctx context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	row, err := p.q.GetAccountByWalletScopeAndName(
		ctx, sqlc.GetAccountByWalletScopeAndNameParams{
			WalletID:    int64(query.WalletID),
			Purpose:     int64(query.Scope.Purpose),
			CoinType:    int64(query.Scope.Coin),
			AccountName: *query.Name,
		},
	)
	if err != nil {
		return nil, mapGetAccountErr(err, query)
	}

	info, err := accountRowToInfo(row)
	if err != nil {
		return nil, err
	}

	return p.attachBalance(ctx, query, info, row.ID)
}

// attachBalance fills ConfirmedBalance and UnconfirmedBalance on info via
// the dedicated AccountBalance query, unless the caller opted out via
// query.SkipBalance. The query runs inside the caller's read transaction.
func (p accountGetQueries) attachBalance(ctx context.Context,
	query db.GetAccountQuery, info *db.AccountInfo,
	accountID int64) (*db.AccountInfo, error) {

	if query.SkipBalance {
		return info, nil
	}

	bal, err := p.q.AccountBalance(
		ctx, sqlc.AccountBalanceParams{
			WalletID:  int64(query.WalletID),
			AccountID: accountID,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("account balance: %w", err)
	}

	info.ConfirmedBalance = btcutil.Amount(bal.ConfirmedBalance)
	info.UnconfirmedBalance = btcutil.Amount(bal.UnconfirmedBalance)

	return info, nil
}

// mapGetAccountErr returns the typed ErrAccountNotFound when err is
// sql.ErrNoRows, falling back to a wrapped form otherwise. The caller
// names the queried account in the error using whichever selector
// (Name or AccountNumber) was set.
func mapGetAccountErr(err error, query db.GetAccountQuery) error {
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("get account: %w", err)
	}

	if query.Name != nil {
		return fmt.Errorf("account %q in scope %d/%d: %w", *query.Name,
			query.Scope.Purpose, query.Scope.Coin,
			db.ErrAccountNotFound)
	}

	return fmt.Errorf("account %d in scope %d/%d: %w",
		*query.AccountNumber, query.Scope.Purpose, query.Scope.Coin,
		db.ErrAccountNotFound)
}

// accountRenameQueries groups PostgreSQL account rename query methods.
type accountRenameQueries struct {
	q *sqlc.Queries
}

// byNumber renames an account identified by wallet ID, scope, and account
// number.
func (p accountRenameQueries) byNumber(ctx context.Context,
	params db.RenameAccountParams) error {

	return db.RenameAccount(
		ctx, p.q.UpdateAccountNameByWalletScopeAndNumber,
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
func (p accountRenameQueries) byName(ctx context.Context,
	params db.RenameAccountParams) error {

	return db.RenameAccount(
		ctx, p.q.UpdateAccountNameByWalletScopeAndName,
		sqlc.UpdateAccountNameByWalletScopeAndNameParams{
			NewName:  params.NewName,
			WalletID: int64(params.WalletID),
			Purpose:  int64(params.Scope.Purpose),
			CoinType: int64(params.Scope.Coin),
			OldName:  params.OldName,
		}, params,
	)
}
