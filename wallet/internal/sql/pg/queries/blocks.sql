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
-- InsertBlock arbitrates both unique keys when wallets insert a shared block.
-- ensureBlockExists still verifies the stored hash and timestamp afterward.
ON CONFLICT DO NOTHING;

-- name: DeleteBlock :exec
DELETE FROM blocks
WHERE block_height = $1;
