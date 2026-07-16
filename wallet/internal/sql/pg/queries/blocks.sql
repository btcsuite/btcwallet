-- name: GetBlockByHeight :one
-- A height can host competing blocks, so the oldest recorded block at the
-- height is returned deterministically. Fork disambiguation by id is a later
-- increment.
SELECT
    block_height,
    header_hash,
    block_timestamp
FROM blocks
WHERE block_height = $1
ORDER BY id
LIMIT 1;

-- name: GetBlocksInRange :many
SELECT
    block_height,
    header_hash,
    block_timestamp
FROM blocks
WHERE
    block_height BETWEEN
    sqlc.arg('start_height')::INTEGER
    AND sqlc.arg('end_height')::INTEGER
ORDER BY block_height;

-- name: InsertBlock :one
INSERT INTO blocks (block_height, header_hash, block_timestamp)
VALUES ($1, $2, $3)
RETURNING id;

-- name: PutBlock :exec
-- PutBlock inserts the block or, when a block with the same globally unique
-- header hash already exists, leaves it untouched. A different hash at the same
-- height inserts a distinct row, so competing same-height blocks coexist and no
-- block is ever overwritten.
INSERT INTO blocks (block_height, header_hash, block_timestamp)
VALUES ($1, $2, $3)
ON CONFLICT (header_hash) DO NOTHING;

-- name: DeleteBlock :exec
DELETE FROM blocks
WHERE id = $1;

-- name: PruneStaleSyncBlock :exec
-- PruneStaleSyncBlock removes blocks that have aged out of the recent-block
-- retention window at the given height, mirroring the legacy address manager's
-- per-tip pruning. The shared blocks table is foreign-keyed by transactions and
-- wallet sync states with ON DELETE RESTRICT, so a block is only removed when
-- nothing still references it.
DELETE FROM blocks
WHERE blocks.block_height = $1
  AND NOT EXISTS (
      SELECT 1 FROM transactions
      WHERE transactions.block_id = blocks.id
  )
  AND NOT EXISTS (
      SELECT 1 FROM wallet_sync_states
      WHERE wallet_sync_states.start_block_id = blocks.id
          OR wallet_sync_states.synced_block_id = blocks.id
          OR wallet_sync_states.birthday_block_id = blocks.id
  );
