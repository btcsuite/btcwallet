package pg

import (
	"context"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// LeaseOutputs atomically acquires or renews leases for a complete UTXO set.
//
// Every lease write runs inside one write transaction. The first failure
// aborts the callback, which rolls back any lease already written by this
// call, so callers observe either the whole set leased or none of it.
func (s *Store) LeaseOutputs(ctx context.Context,
	params db.LeaseOutputsParams) ([]db.LeasedOutput, error) {

	var leases []db.LeasedOutput

	err := s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		acquired, err := db.LeaseOutputsWithOps(
			ctx, params, &leaseOutputOps{qtx: qtx},
		)
		if err != nil {
			return err
		}

		leases = acquired

		return nil
	})
	if err != nil {
		return nil, err
	}

	return leases, nil
}
