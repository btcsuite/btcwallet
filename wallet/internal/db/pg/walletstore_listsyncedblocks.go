package pg

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// ListSyncedBlocks returns block metadata for the inclusive height range.
func (s *Store) ListSyncedBlocks(ctx context.Context,
	query db.ListSyncedBlocksQuery) ([]db.Block, error) {

	if query.EndHeight < query.StartHeight {
		return nil, fmt.Errorf("%w: end height before start height",
			db.ErrInvalidParam)
	}

	start, err := db.Uint32ToInt32(query.StartHeight)
	if err != nil {
		return nil, fmt.Errorf("convert start height %d: %w",
			query.StartHeight, err)
	}

	end, err := db.Uint32ToInt32(query.EndHeight)
	if err != nil {
		return nil, fmt.Errorf("convert end height %d: %w",
			query.EndHeight, err)
	}

	expected := int(query.EndHeight - query.StartHeight + 1)
	blocks := make([]db.Block, 0, expected)

	err = s.execRead(ctx, func(q *sqlc.Queries) error {
		// One range read returns every stored block in the window in
		// ascending height order, replacing the previous per-height
		// lookup loop.
		rows, err := q.GetBlocksInRange(ctx, sqlc.GetBlocksInRangeParams{
			StartHeight: start,
			EndHeight:   end,
		})
		if err != nil {
			return fmt.Errorf("get blocks in range [%d, %d]: %w",
				query.StartHeight, query.EndHeight, err)
		}

		// The caller maps the result positionally onto a contiguous
		// height range, so a gap must hard-error exactly as the old
		// per-height loop did. Walking the expected heights alongside
		// the ascending rows detects the first missing height.
		height := query.StartHeight
		for i := range rows {
			row := rows[i]

			block, err := buildBlock(
				sql.NullInt32{Int32: row.BlockHeight, Valid: true},
				row.HeaderHash,
				sql.NullInt64{
					Int64: row.BlockTimestamp,
					Valid: true,
				},
			)
			if err != nil {
				return err
			}

			if block.Height != height {
				return fmt.Errorf("get block %d: %w", height,
					sql.ErrNoRows)
			}

			blocks = append(blocks, *block)
			height++
		}

		// Any heights left after consuming every row are missing from
		// the tail of the range.
		if len(blocks) != expected {
			return fmt.Errorf("get block %d: %w", height,
				sql.ErrNoRows)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return blocks, nil
}
