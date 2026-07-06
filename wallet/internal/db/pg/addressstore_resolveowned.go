package pg

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// ResolveOwnedAddresses resolves a batch of script pubkeys to the wallet-owned
// subset using a single query.
func (s *Store) ResolveOwnedAddresses(ctx context.Context,
	query db.ResolveOwnedAddressesQuery) (map[string]*db.AddressInfo, error) {

	owned := make(map[string]*db.AddressInfo)

	// An empty request resolves to an empty result without issuing a query.
	if len(query.ScriptPubKeys) == 0 {
		return owned, nil
	}

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		rows, err := q.ListAddressesByScriptPubKeys(
			ctx, sqlc.ListAddressesByScriptPubKeysParams{
				WalletID:      int64(query.WalletID),
				ScriptPubKeys: query.ScriptPubKeys,
			},
		)
		if err != nil {
			return fmt.Errorf("list addresses by scripts: %w", err)
		}

		for _, row := range rows {
			info, err := addressRowToInfo(row)
			if err != nil {
				return fmt.Errorf("map address row: %w", err)
			}

			owned[string(info.ScriptPubKey)] = info
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return owned, nil
}
