package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"math"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// syncedBlockSpan returns the inclusive range length after a safe int32 cast.
func syncedBlockSpan(startHeight, endHeight uint32) (int32, error) {
	span := uint64(endHeight) - uint64(startHeight) + 1
	if span > math.MaxInt32 {
		return 0, fmt.Errorf("could not cast synced block span %d to "+
			"int32: %w", span, db.ErrCastingOverflow)
	}

	return int32(span), nil
}

// ListSyncedBlocks returns block metadata for the inclusive height range.
func (s *Store) ListSyncedBlocks(ctx context.Context,
	query db.ListSyncedBlocksQuery) ([]db.Block, error) {

	if query.EndHeight < query.StartHeight {
		return nil, fmt.Errorf("%w: end height before start height",
			db.ErrInvalidParam)
	}

	// Range-check the inclusive span before using it as a slice capacity.
	// The subtraction is done in uint64 so a full-width uint32 range cannot
	// wrap to zero before validation.
	expected, err := syncedBlockSpan(query.StartHeight, query.EndHeight)
	if err != nil {
		return nil, fmt.Errorf("synced block span: %w", err)
	}

	blocks := make([]db.Block, 0, int(expected))

	err = s.execRead(ctx, func(q *sqlc.Queries) error {
		// One range read returns every stored block in the window in
		// ascending height order, replacing the previous per-height
		// lookup loop.
		rows, err := q.GetBlocksInRange(ctx, sqlc.GetBlocksInRangeParams{
			StartHeight: int64(query.StartHeight),
			EndHeight:   int64(query.EndHeight),
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
				sql.NullInt64{Int64: row.BlockHeight, Valid: true},
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
		if len(blocks) != int(expected) {
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
