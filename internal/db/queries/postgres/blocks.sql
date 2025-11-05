-- name: GetBlockByHeight :one
SELECT block_height, header_hash, timestamp
FROM blocks
WHERE block_height = $1;

-- name: InsertBlock :exec
INSERT INTO blocks (block_height, header_hash, timestamp)
VALUES ($1, $2, $3);

-- name: DeleteBlock :exec
DELETE FROM blocks
WHERE block_height = $1;
