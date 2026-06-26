package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// UpdateWalletSecrets updates the secrets for the wallet.
func (s *Store) UpdateWalletSecrets(ctx context.Context,
	params db.UpdateWalletSecretsParams) error {

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		return db.UpdateWalletSecretsWithOps(
			ctx, params, updateWalletSecretsOps{q: qtx},
		)
	})
}

// updateWalletSecretsOps adapts SQLite sqlc queries to the shared
// UpdateWalletSecrets workflow.
type updateWalletSecretsOps struct {
	q *sqlc.Queries
}

// Ensure updateWalletSecretsOps implements db.UpdateWalletSecretsOps.
var _ db.UpdateWalletSecretsOps = (*updateWalletSecretsOps)(nil)

// WalletWatchOnly implements db.UpdateWalletSecretsOps.
func (o updateWalletSecretsOps) WalletWatchOnly(ctx context.Context,
	walletID uint32) (bool, error) {

	walletRow, err := o.q.GetWalletByID(ctx, int64(walletID))
	if err == nil {
		return walletRow.IsWatchOnly, nil
	}

	if errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("wallet %d: %w", walletID,
			db.ErrWalletNotFound)
	}

	return false, err
}

// UpdateWalletSecrets implements db.UpdateWalletSecretsOps.
func (o updateWalletSecretsOps) UpdateWalletSecrets(ctx context.Context,
	params db.UpdateWalletSecretsParams) error {

	rowsAffected, err := o.q.UpdateWalletSecrets(
		ctx, sqlc.UpdateWalletSecretsParams{
			MasterPrivParams: db.NilIfEmptyBytes(
				params.MasterPrivParams,
			),
			EncryptedCryptoPrivKey: db.NilIfEmptyBytes(
				params.EncryptedCryptoPrivKey,
			),
			EncryptedCryptoScriptKey: db.NilIfEmptyBytes(
				params.EncryptedCryptoScriptKey,
			),
			EncryptedMasterHdPrivKey: db.NilIfEmptyBytes(
				params.EncryptedMasterHdPrivKey,
			),
			WalletID: int64(params.WalletID),
		},
	)
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("wallet secrets for wallet %d: %w",
			params.WalletID, db.ErrSecretNotFound)
	}

	return nil
}
