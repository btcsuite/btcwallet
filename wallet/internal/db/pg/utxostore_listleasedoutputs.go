package pg

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// ListLeasedOutputs lists all active leases for current wallet-owned UTXOs.
func (s *Store) ListLeasedOutputs(ctx context.Context,
	walletID uint32) ([]db.LeasedOutput, error) {

	nowUTC := time.Now().UTC()

	var leases []db.LeasedOutput

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		rows, err := q.ListActiveUtxoLeases(
			ctx, sqlc.ListActiveUtxoLeasesParams{
				WalletID: int64(walletID),
				NowUtc:   nowUTC,
			},
		)
		if err != nil {
			return fmt.Errorf("list active utxo leases: %w", err)
		}

		leases = make([]db.LeasedOutput, len(rows))
		for i, row := range rows {
			outputIndex, err := db.Int64ToUint32(int64(row.OutputIndex))
			if err != nil {
				return fmt.Errorf("lease output index: %w", err)
			}

			lease, err := db.BuildLeasedOutput(
				row.TxHash, outputIndex, row.LockID, row.ExpiresAt,
			)
			if err != nil {
				return err
			}

			leases[i] = *lease
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return leases, nil
}
