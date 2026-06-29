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

	var info *db.AccountInfo

	err := s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		var err error

		info, err = db.CreateImportedAccountWithOps(
			ctx, params, createImportedAccountOps{q: qtx},
		)
		if err != nil {
			return err
		}

		if params.DryRun {
			return errDryRunRollback
		}

		return nil
	})
	if err != nil {
		if params.DryRun && errors.Is(err, errDryRunRollback) {
			return info, nil
		}

		return nil, err
	}

	return info, nil
}

// createImportedAccountOps adapts SQLite sqlc queries to the shared
// CreateImportedAccount workflow.
type createImportedAccountOps struct {
	q *sqlc.Queries
}

// Verify createImportedAccountOps implements db.CreateImportedAccountOps.
var _ db.CreateImportedAccountOps = createImportedAccountOps{}

// IsWalletWatchOnly implements db.CreateImportedAccountOps.
func (o createImportedAccountOps) IsWalletWatchOnly(ctx context.Context,
	walletID uint32) (bool, error) {

	return getWalletWatchOnly(ctx, o.q, walletID)
}

// EnsureKeyScope implements db.CreateImportedAccountOps.
func (o createImportedAccountOps) EnsureKeyScope(ctx context.Context,
	walletID uint32, scope db.KeyScope,
	addrSchema *db.ScopeAddrSchema) (int64, error) {

	return db.EnsureKeyScopeWithOps(
		ctx, sqliteEnsureKeyScopeOps(o), walletID, scope, addrSchema,
	)
}

// CreateImportedAccount implements db.CreateImportedAccountOps.
func (o createImportedAccountOps) CreateImportedAccount(ctx context.Context,
	req db.CreateImportedAccountInsertRequest) (int64, error) {

	row, err := o.q.CreateImportedAccount(
		ctx, sqlc.CreateImportedAccountParams{
			ScopeID:     req.ScopeID,
			AccountName: req.Name,
			PublicKey:   req.PublicKey,
			MasterFingerprint: sql.NullInt64{
				Int64: int64(req.MasterFingerprint),
				Valid: true,
			},
		},
	)
	if err != nil {
		return 0, err
	}

	return row.ID, nil
}

// CreateAccountSecret implements db.CreateImportedAccountOps.
func (o createImportedAccountOps) CreateAccountSecret(ctx context.Context,
	accountID int64, encryptedPrivateKey []byte) error {

	return o.q.CreateAccountSecret(
		ctx, sqlc.CreateAccountSecretParams{
			AccountID: accountID,
			EncryptedPrivateKey: db.NilIfEmptyBytes(
				encryptedPrivateKey,
			),
		},
	)
}

// GetAccountInfoByID implements db.CreateImportedAccountOps.
func (o createImportedAccountOps) GetAccountInfoByID(ctx context.Context,
	accountID int64) (*db.AccountInfo, error) {

	return getAccountProps(ctx, o.q, accountID)
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

// getAccountProps fetches full account properties from the database and
// converts the row to AccountInfo.
func getAccountProps(ctx context.Context, qtx *sqlc.Queries,
	accountID int64) (*db.AccountInfo, error) {

	row, err := qtx.GetAccountPropsById(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("get account props: %w", err)
	}

	return db.AccountPropsRowToInfo(db.AccountPropsRow[int64]{
		RowID:             accountID,
		AccountNumber:     row.AccountNumber,
		AccountName:       row.AccountName,
		IsDerived:         row.IsDerived,
		ExternalKeyCount:  row.ExternalKeyCount,
		InternalKeyCount:  row.InternalKeyCount,
		PublicKey:         row.PublicKey,
		MasterFingerprint: row.MasterFingerprint,
		IsWatchOnly:       row.WalletIsWatchOnly,
		CreatedAt:         row.CreatedAt,
		Purpose:           row.Purpose,
		CoinType:          row.CoinType,
		InternalTypeID:    row.InternalTypeID,
		ExternalTypeID:    row.ExternalTypeID,
	})
}
