-- name: GetBlockByHeight :one
SELECT
    block_height,
    header_hash,
    block_timestamp
FROM blocks
WHERE block_height = ?;

-- name: InsertBlock :exec
INSERT OR IGNORE INTO blocks (block_height, header_hash, block_timestamp)
VALUES (?, ?, ?);

-- name: DeleteBlock :exec
DELETE FROM blocks
WHERE block_height = ?;
