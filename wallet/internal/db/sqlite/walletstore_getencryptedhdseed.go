package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// GetEncryptedHDSeed retrieves the encrypted Hierarchical
// Deterministic (HD) seed (the encrypted master HD private key) of
// the wallet. This seed is sensitive information and is returned in
// its encrypted form. It returns the encrypted seed as a byte slice
// or an error if the retrieval fails.
func (s *Store) GetEncryptedHDSeed(ctx context.Context,
	walletID uint32) ([]byte, error) {

	var encrypted []byte

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		secrets, err := q.GetWalletSecrets(ctx, int64(walletID))
		if err == nil {
			if len(secrets.EncryptedMasterHdPrivKey) == 0 {
				return fmt.Errorf(
					"encrypted master privkey for wallet %d: %w", walletID,
					db.ErrSecretNotFound)
			}

			encrypted = secrets.EncryptedMasterHdPrivKey

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

	return encrypted, nil
}
