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
