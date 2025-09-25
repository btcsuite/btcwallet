-- name: GetAddrBlockByHeight :one
SELECT height, hash, timestamp FROM addr_blocks WHERE height = $1;

-- name: GetAddrBlockByHash :one
SELECT height, hash, timestamp FROM addr_blocks WHERE hash = $1;

-- name: InsertAddrBlock :exec
INSERT INTO addr_blocks (height, hash, timestamp)
VALUES ($1, $2, $3);

-- name: DeleteAddrBlock :exec
DELETE FROM addr_blocks WHERE height = $1;

-- name: GetLatestAddrBlock :one
SELECT height, hash, timestamp FROM addr_blocks ORDER BY height DESC LIMIT 1;
