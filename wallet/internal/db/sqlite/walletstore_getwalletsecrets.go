package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// resolveWalletSecretsLookupErr maps a missing wallet_secrets row to the
// appropriate error by checking wallet existence. If the wallet exists,
// returns ErrSecretNotFound. If the wallet is also missing, returns
// ErrWalletNotFound. If the wallet check fails, wraps and returns that error.
func resolveWalletSecretsLookupErr(ctx context.Context, q *sqlc.Queries,
	walletID uint32) error {

	_, walletErr := q.GetWalletByID(ctx, int64(walletID))
	if walletErr == nil {
		return fmt.Errorf("secrets for wallet %d: %w", walletID,
			db.ErrSecretNotFound)
	}

	if errors.Is(walletErr, sql.ErrNoRows) {
		return fmt.Errorf("wallet %d: %w", walletID, db.ErrWalletNotFound)
	}

	return fmt.Errorf("get wallet %d after missing secrets: %w", walletID,
		walletErr)
}

// GetWalletSecrets retrieves the encrypted secret material for one wallet.
func (s *Store) GetWalletSecrets(ctx context.Context,
	walletID uint32) (*db.WalletSecrets, error) {

	var secretsInfo *db.WalletSecrets

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		secrets, err := q.GetWalletSecrets(ctx, int64(walletID))
		if err == nil {
			secretsInfo = &db.WalletSecrets{
				MasterPrivParams:         secrets.MasterPrivParams,
				EncryptedCryptoPrivKey:   secrets.EncryptedCryptoPrivKey,
				EncryptedCryptoScriptKey: secrets.EncryptedCryptoScriptKey,
				EncryptedMasterHdPrivKey: secrets.EncryptedMasterHdPrivKey,
			}

			return nil
		}

		if errors.Is(err, sql.ErrNoRows) {
			return resolveWalletSecretsLookupErr(ctx, q, walletID)
		}

		return fmt.Errorf("get wallet secrets: %w", err)
	})
	if err != nil {
		return nil, err
	}

	return secretsInfo, nil
}
