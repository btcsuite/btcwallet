package sqlite

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// LoadWatchSet returns persisted address scripts and outpoints in one snapshot.
// Native subscriptions remain the caller's responsibility.
func (s *Store) LoadWatchSet(ctx context.Context, walletID uint32) (db.WatchSet,
	error) {

	var watches db.WatchSet

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		rows, err := q.LoadWatchSet(ctx, int64(walletID))
		if err != nil {
			return fmt.Errorf("load watch set: %w", err)
		}

		// Each read attempt replaces its predecessor if execRead retries.
		watches = db.WatchSet{}
		for _, row := range rows {
			// The discriminator keeps address rows separate from outputs.
			if row.IsOutpoint == 0 {
				watches.AddressScripts = append(
					watches.AddressScripts, row.ScriptPubKey,
				)

				continue
			}

			hash, err := chainhash.NewHash(row.TxHash)
			if err != nil {
				return fmt.Errorf("watch output hash: %w", err)
			}

			index, err := db.Int64ToUint32(row.OutputIndex)
			if err != nil {
				return fmt.Errorf("watch output index: %w", err)
			}

			watches.OutPoints = append(watches.OutPoints, wire.OutPoint{
				Hash:  *hash,
				Index: index,
			})
		}

		return nil
	})
	if err != nil {
		return db.WatchSet{}, err
	}

	return watches, nil
}
