package sqlite

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// ListOutputsToWatch returns UTXOs that recovery scans should watch.
//
// The result mirrors the legacy wtxmgr OutputsToWatch contract: it returns
// every known output (unspent, locked, or spent only by an unmined
// transaction) but populates just the OutPoint and PkScript, since those are
// the only fields a rescan consumes.
func (s *Store) ListOutputsToWatch(ctx context.Context,
	walletID uint32) ([]db.UtxoInfo, error) {

	var utxos []db.UtxoInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		rows, err := q.ListOutputsToWatch(ctx, int64(walletID))
		if err != nil {
			return fmt.Errorf("list outputs to watch: %w", err)
		}

		utxos = make([]db.UtxoInfo, len(rows))
		for i, row := range rows {
			utxo, err := db.WatchOutputFromRow(
				row.TxHash, row.OutputIndex, row.RawTx,
			)
			if err != nil {
				return err
			}

			utxos[i] = *utxo
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(utxos) == 0 {
		return []db.UtxoInfo{}, nil
	}

	return utxos, nil
}
