package pg

import (
	"context"
	"database/sql"
	"fmt"
	"iter"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// ListWallets returns a page of wallets matching the given query.
func (s *Store) ListWallets(ctx context.Context,
	query db.ListWalletsQuery) (page.Result[db.WalletInfo, uint32], error) {

	if query.Page.Limit() == 0 {
		return page.Result[db.WalletInfo, uint32]{}, db.ErrInvalidPageLimit
	}

	var items []db.WalletInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		rows, err := q.ListWallets(ctx, listWalletsParams(query.Page))
		if err != nil {
			return fmt.Errorf("list wallets page: %w", err)
		}

		items = make([]db.WalletInfo, len(rows))
		for i, row := range rows {
			item, errMap := walletRowToInfo(row)
			if errMap != nil {
				return fmt.Errorf("list wallets page: map row: %w", errMap)
			}

			items[i] = *item
		}

		return nil
	})
	if err != nil {
		return page.Result[db.WalletInfo, uint32]{}, err
	}

	result := page.BuildResult(
		query.Page, items,
		func(item db.WalletInfo) uint32 {
			return item.ID
		},
	)

	return result, nil
}

// IterWallets returns an iterator over paginated wallet results.
func (s *Store) IterWallets(ctx context.Context,
	query db.ListWalletsQuery) iter.Seq2[db.WalletInfo, error] {

	return page.Iter(
		ctx, query, s.ListWallets, db.NextListWalletsQuery,
	)
}

// listWalletsParams translates a page request to ListWallets query
// parameters, handling optional cursor setup for pagination.
func listWalletsParams(
	req page.Request[uint32]) sqlc.ListWalletsParams {

	params := sqlc.ListWalletsParams{
		PageLimit: int64(req.Limit()) + 1,
	}

	if req.After != nil {
		params.CursorID = sql.NullInt64{
			Int64: int64(*req.After),
			Valid: true,
		}
	}

	return params
}
