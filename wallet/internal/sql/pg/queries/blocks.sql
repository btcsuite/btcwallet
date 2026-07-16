-- name: GetBlockByHeight :one
SELECT
    block_height,
    header_hash,
    block_timestamp
FROM blocks
WHERE block_height = $1;

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

-- name: InsertBlock :exec
INSERT INTO blocks (block_height, header_hash, block_timestamp)
VALUES ($1, $2, $3)
ON CONFLICT (block_height) DO NOTHING;

-- name: PutBlock :exec
INSERT INTO blocks (block_height, header_hash, block_timestamp)
VALUES ($1, $2, $3)
ON CONFLICT (block_height) DO UPDATE SET
    header_hash = excluded.header_hash,
    block_timestamp = excluded.block_timestamp;

-- name: DeleteBlock :exec
DELETE FROM blocks
WHERE block_height = $1;

-- name: PruneStaleSyncBlock :exec
-- PruneStaleSyncBlock removes one block that has aged out of the recent-block
-- retention window, mirroring the legacy address manager's per-tip pruning.
-- The shared blocks table is foreign-keyed by transactions and wallet sync
-- states with ON DELETE RESTRICT, so the block is only removed when nothing
-- still references it.
DELETE FROM blocks
WHERE blocks.block_height = $1
  AND NOT EXISTS (
      SELECT 1 FROM transactions
      WHERE transactions.block_height = blocks.block_height
  )
  AND NOT EXISTS (
      SELECT 1 FROM wallet_sync_states
      WHERE wallet_sync_states.start_block_height = blocks.block_height
          OR wallet_sync_states.synced_block_height = blocks.block_height
          OR wallet_sync_states.birthday_block_height = blocks.block_height
  );
