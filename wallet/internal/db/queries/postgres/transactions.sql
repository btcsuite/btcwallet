-- name: InsertTransaction :one
-- Inserts a new transaction record.
-- For confirmed transactions, block_height must be set.
-- For unconfirmed transactions, block_height should be NULL.
-- Returns the auto-generated ID.
INSERT INTO transactions (tx_hash, block_height, is_coinbase, received_timestamp, serialized_tx, tx_label)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tx_hash, block_height) DO NOTHING
RETURNING id;

-- name: GetTransactionByHash :one
-- Gets a transaction by hash with priority: unconfirmed first, then highest confirmed block.
SELECT
    t.id,
    t.tx_hash,
    t.block_height,
    t.is_coinbase,
    t.received_timestamp,
    t.serialized_tx,
    t.tx_label,
    b.header_hash,
    b.block_timestamp
FROM transactions AS t
LEFT JOIN blocks AS b ON t.block_height = b.block_height
WHERE t.tx_hash = $1
ORDER BY t.block_height DESC NULLS FIRST
LIMIT 1;

-- name: GetTransactionByHashAndBlock :one
-- Retrieves a confirmed transaction by its hash and block height.
SELECT
    id,
    tx_hash,
    block_height,
    is_coinbase,
    received_timestamp,
    serialized_tx,
    tx_label
FROM transactions
WHERE tx_hash = $1 AND block_height = $2;

-- name: GetUnconfirmedTransactionByHash :one
-- Retrieves an unconfirmed transaction by its hash.
SELECT
    id,
    tx_hash,
    block_height,
    is_coinbase,
    received_timestamp,
    serialized_tx,
    tx_label
FROM transactions
WHERE tx_hash = $1 AND block_height IS NULL;

-- name: GetLatestConfirmedTransactionByHash :one
-- Gets the most recent CONFIRMED (mined) transaction with a given hash.
-- Returns only confirmed transactions, ordered by highest block.
SELECT
    id,
    tx_hash,
    block_height,
    is_coinbase,
    received_timestamp,
    serialized_tx,
    tx_label
FROM transactions
WHERE tx_hash = $1 AND block_height IS NOT NULL
ORDER BY block_height DESC
LIMIT 1;

-- name: TransactionExists :one
-- Checks if a transaction with the given hash and block exists.
SELECT exists(
    SELECT 1 FROM transactions
    WHERE tx_hash = $1 AND block_height = $2
);

-- name: UnconfirmedTransactionExists :one
-- Checks if an unconfirmed transaction with the given hash exists.
SELECT exists(
    SELECT 1 FROM transactions
    WHERE tx_hash = $1 AND block_height IS NULL
);

-- name: DeleteTransaction :exec
-- Deletes a specific confirmed transaction by hash and block height.
-- Used during blockchain reorganizations.
DELETE FROM transactions
WHERE tx_hash = $1 AND block_height = $2;

-- name: DeleteUnconfirmedTransaction :exec
-- Deletes an unconfirmed transaction by its hash.
-- Used when removing transactions from the mempool.
DELETE FROM transactions
WHERE tx_hash = $1 AND block_height IS NULL;

-- name: GetAllUnconfirmedTransactions :many
-- Retrieves all unconfirmed (mempool) transactions.
-- Ordered by received timestamp.
SELECT
    id,
    tx_hash,
    block_height,
    is_coinbase,
    received_timestamp,
    serialized_tx,
    tx_label
FROM transactions
WHERE block_height IS NULL
ORDER BY received_timestamp ASC;

-- name: GetAllUnconfirmedTransactionHashes :many
-- Retrieves all unconfirmed transaction hashes only.
SELECT tx_hash
FROM transactions
WHERE block_height IS NULL
ORDER BY received_timestamp ASC;

-- name: GetAllConfirmedTransactionsByHash :many
-- Gets all CONFIRMED transactions with a given hash.
-- Used to find duplicates across blocks during reorganizations.
SELECT
    id,
    tx_hash,
    block_height,
    is_coinbase,
    received_timestamp,
    serialized_tx,
    tx_label
FROM transactions
WHERE tx_hash = $1 AND block_height IS NOT NULL
ORDER BY block_height DESC;

-- name: UpdateTransactionBlock :exec
-- Updates the block height of a transaction (for confirming transactions).
UPDATE transactions
SET block_height = $2
WHERE tx_hash = $1 AND block_height IS NULL;

-- name: UpdateTransactionLabel :exec
-- Updates the label of a transaction.
UPDATE transactions
SET tx_label = $2
WHERE tx_hash = $1;

-- name: UnconfirmTransactionsFromHeight :exec
-- Moves all transactions at or after a given height back to unconfirmed.
-- Used during blockchain reorganizations.
UPDATE transactions
SET block_height = NULL
WHERE block_height >= $1;

-- name: ListTransactionsByHeightRange :many
-- Retrieves transactions within a block height range, with block metadata.
-- Returns transactions ordered by block height and received timestamp.
SELECT
    t.id,
    t.tx_hash,
    t.block_height,
    t.is_coinbase,
    t.received_timestamp,
    t.serialized_tx,
    t.tx_label,
    b.header_hash,
    b.block_timestamp
FROM transactions AS t
LEFT JOIN blocks AS b ON t.block_height = b.block_height
WHERE t.block_height >= $1 AND t.block_height <= $2
ORDER BY t.block_height ASC, t.received_timestamp ASC;
