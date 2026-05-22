package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

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
			return fmt.Errorf("secrets for wallet %d: %w", walletID,
				db.ErrWalletNotFound)
		}

		return fmt.Errorf("get wallet secrets: %w", err)
	})
	if err != nil {
		return nil, err
	}

	return secretsInfo, nil
}
