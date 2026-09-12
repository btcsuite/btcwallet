package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"iter"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// ListAddresses returns a page of addresses matching the given query.
func (s *Store) ListAddresses(ctx context.Context,
	query db.ListAddressesQuery) (page.Result[db.AddressInfo, uint32], error) {

	var empty page.Result[db.AddressInfo, uint32]

	if query.Page.Limit() == 0 {
		return empty, db.ErrInvalidPageLimit
	}

	target, err := query.Target()
	if err != nil {
		return empty, err
	}

	var items []db.AddressInfo

	err = s.execRead(ctx, func(q *sqlc.Queries) error {
		var err error

		switch target {
		case db.ListTargetRawImported:
			items, err = listRawImportedAddresses(ctx, q, query)

		case db.ListTargetByAccount:
			items, err = listAddressesByAccount(ctx, q, query)
		}

		return err
	})
	if err != nil {
		return empty, err
	}

	return page.BuildResult(
		query.Page, items,
		func(item db.AddressInfo) uint32 {
			return item.ID
		},
	), nil
}

// IterAddresses returns an iterator over paginated address results.
func (s *Store) IterAddresses(ctx context.Context,
	query db.ListAddressesQuery) iter.Seq2[db.AddressInfo, error] {

	return page.Iter(
		ctx, query, s.ListAddresses, db.NextListAddressesQuery,
	)
}

// listAddressesByAccount lists the addresses owned by the account named by the
// query's key scope and account name, with pagination support.
func listAddressesByAccount(ctx context.Context, q *sqlc.Queries,
	query db.ListAddressesQuery) ([]db.AddressInfo, error) {

	rows, err := q.ListAddressesByAccount(ctx, buildAddressPageParams(query))
	if err != nil {
		return nil, fmt.Errorf("list addresses by account: %w", err)
	}

	items := make([]db.AddressInfo, len(rows))
	for i, row := range rows {
		item, err := addressRowToInfo(row)
		if err != nil {
			return nil,
				fmt.Errorf("list addresses by account: map address row: %w",
					err)
		}

		items[i] = *item
	}

	return items, nil
}

// listRawImportedAddresses lists raw imported addresses for the imported alias.
func listRawImportedAddresses(ctx context.Context, q *sqlc.Queries,
	query db.ListAddressesQuery) ([]db.AddressInfo, error) {

	rows, err := q.ListRawImportedAddresses(
		ctx, sqlc.ListRawImportedAddressesParams{
			WalletID:  int64(query.WalletID),
			PageLimit: int64(query.Page.Limit()) + 1,
			CursorID:  rawAddressCursor(query),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list raw imported addresses: %w", err)
	}

	items := make([]db.AddressInfo, len(rows))
	for i, row := range rows {
		item, err := addressRowToInfo(row)
		if err != nil {
			return nil, fmt.Errorf("list raw imported addresses: %w", err)
		}

		items[i] = *item
	}

	return items, nil
}

// rawAddressCursor converts an optional page cursor into a nullable sqlc value.
func rawAddressCursor(q db.ListAddressesQuery) sql.NullInt64 {
	if q.Page.After == nil {
		return sql.NullInt64{}
	}

	return sql.NullInt64{
		Int64: int64(*q.Page.After),
		Valid: true,
	}
}

// buildAddressPageParams translates a ListAddresses query to
// ListAddressesByAccount parameters, handling pagination cursors.
func buildAddressPageParams(
	q db.ListAddressesQuery) sqlc.ListAddressesByAccountParams {

	params := sqlc.ListAddressesByAccountParams{
		WalletID:    int64(q.WalletID),
		Purpose:     int64(q.Scope.Purpose),
		CoinType:    int64(q.Scope.Coin),
		AccountName: *q.AccountName,
		PageLimit:   int64(q.Page.Limit()) + 1,
	}

	if q.Page.After != nil {
		params.CursorID = int64(*q.Page.After)
	}

	return params
}
