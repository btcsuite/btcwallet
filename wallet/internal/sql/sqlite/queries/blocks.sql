-- name: GetBlockByHeight :one
SELECT
    block_height,
    header_hash,
    block_timestamp
FROM blocks
WHERE block_height = ?;

-- name: GetBlocksInRange :many
SELECT
    block_height,
    header_hash,
    block_timestamp
FROM blocks
WHERE
    block_height >= cast(sqlc.arg('start_height') AS INTEGER)
    AND block_height <= cast(sqlc.arg('end_height') AS INTEGER)
ORDER BY block_height;

-- name: InsertBlock :exec
INSERT OR IGNORE INTO blocks (block_height, header_hash, block_timestamp)
VALUES (?, ?, ?);

-- name: PutBlock :exec
INSERT INTO blocks (block_height, header_hash, block_timestamp)
VALUES (?, ?, ?)
ON CONFLICT (block_height) DO UPDATE SET
    header_hash = excluded.header_hash,
    block_timestamp = excluded.block_timestamp;

-- name: DeleteBlock :exec
DELETE FROM blocks
WHERE block_height = ?;
