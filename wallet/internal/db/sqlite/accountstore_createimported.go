package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

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
				id, _, err := ensureKeyScope(
					ctx, qtx, params.WalletID, params.Scope,
					params.AddrSchema,
				)

				return id, err
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
		InternalTypeID:    row.InternalTypeID,
		ExternalTypeID:    row.ExternalTypeID,
		IDToOriginType:    db.IDToAccountOrigin[int64],
	})
}
