-- name: GetBlockByHeight :one
SELECT
    block_height,
    header_hash,
    created_at
FROM blocks
WHERE block_height = ?;

-- name: InsertBlock :exec
INSERT INTO blocks (block_height, header_hash, created_at)
VALUES (?, ?, ?);

-- name: DeleteBlock :exec
DELETE FROM blocks
WHERE block_height = ?;
