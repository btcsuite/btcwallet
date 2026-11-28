-- name: GetWalletBlockByHeight :one
-- Block identity belongs to one Wallet, including during replacement replay.
SELECT
    block_height,
    header_hash,
    block_timestamp
FROM wallet_blocks
WHERE wallet_id = cast(sqlc.arg('wallet_id') AS INTEGER) AND block_height = cast(sqlc.arg('block_height') AS INTEGER);

-- name: GetWalletBlocksInRange :many
SELECT
    block_height,
    header_hash,
    block_timestamp
FROM wallet_blocks
WHERE
    wallet_id = cast(sqlc.arg('wallet_id') AS INTEGER)
    AND block_height >= cast(sqlc.arg('start_height') AS INTEGER)
    AND block_height <= cast(sqlc.arg('end_height') AS INTEGER)
ORDER BY block_height;

-- name: DeleteWalletBlockByHeight :execrows
-- Delete only a proven orphan; higher current-chain observations stay owned.
DELETE FROM wallet_blocks
WHERE wallet_id = cast(sqlc.arg('wallet_id') AS INTEGER) AND block_height = cast(sqlc.arg('block_height') AS INTEGER);

-- name: InsertWalletBlock :exec
-- Verify conflicts through requireBlockMatches in the same write transaction.
INSERT INTO wallet_blocks (
    wallet_id, block_height, header_hash, block_timestamp
)
VALUES (
    cast(sqlc.arg('wallet_id') AS INTEGER),
    cast(sqlc.arg('block_height') AS INTEGER),
    sqlc.arg('header_hash'),
    sqlc.arg('block_timestamp')
)
ON CONFLICT DO NOTHING; -- Keep data validation errors visible.
