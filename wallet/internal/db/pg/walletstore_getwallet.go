package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// GetWallet retrieves information about a wallet given its name. It
// returns a WalletInfo struct containing the wallet's properties or an
// error if the wallet is not found.
func (s *Store) GetWallet(ctx context.Context, name string) (*db.WalletInfo,
	error) {

	var info *db.WalletInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetWalletByName(ctx, name)
		if err == nil {
			info, err = walletRowToInfo(row)
			return err
		}

		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("wallet %q: %w", name, db.ErrWalletNotFound)
		}

		return fmt.Errorf("get wallet: %w", err)
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}
