-- name: GetBlockByHeight :one
SELECT
    block_height,
    header_hash,
    block_timestamp
FROM wallet_blocks
WHERE wallet_id = sqlc.arg('wallet_id')
  AND block_height = sqlc.arg('block_height');

-- name: GetBlocksInRange :many
SELECT
    block_height,
    header_hash,
    block_timestamp
FROM wallet_blocks
WHERE
    wallet_id = sqlc.arg('wallet_id')
    AND block_height BETWEEN
    sqlc.arg('start_height')::INTEGER
    AND sqlc.arg('end_height')::INTEGER
ORDER BY block_height;

-- name: EnsureBlockHeight :exec
INSERT INTO blocks (block_height, header_hash, block_timestamp)
VALUES ($1, $2, $3)
ON CONFLICT (block_height) DO NOTHING;

-- name: InsertBlock :exec
INSERT INTO wallet_blocks (
    wallet_id, block_height, header_hash, block_timestamp
)
VALUES ($1, $2, $3, $4)
ON CONFLICT (wallet_id, block_height) DO NOTHING;

-- name: PutBlock :exec
INSERT INTO wallet_blocks (
    wallet_id, block_height, header_hash, block_timestamp
)
VALUES ($1, $2, $3, $4)
ON CONFLICT (wallet_id, block_height) DO UPDATE SET
    header_hash = excluded.header_hash,
    block_timestamp = excluded.block_timestamp;

-- name: DeleteBlock :exec
DELETE FROM wallet_blocks
WHERE wallet_id = $1 AND block_height = $2;
