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
    AND block_height >= cast(sqlc.arg('start_height') AS INTEGER)
    AND block_height <= cast(sqlc.arg('end_height') AS INTEGER)
ORDER BY block_height;

-- name: EnsureBlockHeight :exec
INSERT OR IGNORE INTO blocks (block_height, header_hash, block_timestamp)
VALUES (?, ?, ?);

-- name: InsertBlock :exec
INSERT OR IGNORE INTO wallet_blocks (
    wallet_id, block_height, header_hash, block_timestamp
)
VALUES (?, ?, ?, ?);

-- name: PutBlock :exec
INSERT INTO wallet_blocks (
    wallet_id, block_height, header_hash, block_timestamp
)
VALUES (?, ?, ?, ?)
ON CONFLICT (wallet_id, block_height) DO UPDATE SET
    header_hash = excluded.header_hash,
    block_timestamp = excluded.block_timestamp;

-- name: DeleteBlock :exec
DELETE FROM wallet_blocks
WHERE wallet_id = ? AND block_height = ?;
