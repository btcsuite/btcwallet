package sqlite

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// LoadWatchSet returns persisted address scripts and outpoints in one snapshot.
// Native subscriptions remain the caller's responsibility.
func (s *Store) LoadWatchSet(ctx context.Context, walletID uint32) (db.WatchSet,
	error) {

	// Build the result inside each attempt so Read returns a complete
	// snapshot only after the attempt succeeds.
	read := func(ctx context.Context, q *sqlc.Queries) (db.WatchSet, error) {
		rows, err := q.LoadWatchSet(ctx, int64(walletID))
		if err != nil {
			return db.WatchSet{}, fmt.Errorf("load watch set: %w", err)
		}

		var watches db.WatchSet

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
				return db.WatchSet{}, fmt.Errorf(
					"watch output hash: %w", err,
				)
			}

			index, err := db.Int64ToUint32(row.OutputIndex)
			if err != nil {
				return db.WatchSet{}, fmt.Errorf(
					"watch output index: %w", err,
				)
			}

			watches.OutPoints = append(
				watches.OutPoints, wire.OutPoint{
					Hash:  *hash,
					Index: index,
				},
			)
		}

		return watches, nil
	}

	return dbruntime.Read(ctx, s, s.queries, defaultReadConfig(), read)
}
