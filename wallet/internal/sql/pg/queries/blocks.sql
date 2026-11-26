-- name: GetWalletBlockByHeight :one
-- Block identity belongs to one Wallet, including during replacement replay.
SELECT
    block_height,
    header_hash,
    block_timestamp
FROM wallet_blocks
WHERE wallet_id = sqlc.arg('wallet_id')::BIGINT AND block_height = sqlc.arg('block_height')::INTEGER;

-- name: GetWalletBlocksInRange :many
SELECT
    block_height,
    header_hash,
    block_timestamp
FROM wallet_blocks
WHERE
    wallet_id = sqlc.arg('wallet_id')::BIGINT
    AND block_height >= sqlc.arg('start_height')::INTEGER
    AND block_height <= sqlc.arg('end_height')::INTEGER
ORDER BY block_height;

-- name: InsertWalletBlock :exec
-- Verify conflicts through requireBlockMatches in the same write transaction.
INSERT INTO wallet_blocks (
    wallet_id, block_height, header_hash, block_timestamp
)
VALUES (
    sqlc.arg('wallet_id')::BIGINT,
    sqlc.arg('block_height')::INTEGER,
    sqlc.arg('header_hash'),
    sqlc.arg('block_timestamp')
)
ON CONFLICT DO NOTHING;

-- name: DeleteWalletBlockByHeight :execrows
-- Delete only a proven orphan; higher current-chain observations stay owned.
DELETE FROM wallet_blocks
WHERE wallet_id = sqlc.arg('wallet_id')::BIGINT AND block_height = sqlc.arg('block_height')::BIGINT;
