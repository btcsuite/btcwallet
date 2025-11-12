-- name: GetBlockByHeight :one
SELECT block_height, header_hash, timestamp
FROM blocks
WHERE block_height = ?;

-- name: InsertBlock :exec
INSERT INTO blocks (block_height, header_hash, timestamp)
VALUES (?, ?, ?);

-- name: DeleteBlock :exec
DELETE FROM blocks
WHERE block_height = ?;
