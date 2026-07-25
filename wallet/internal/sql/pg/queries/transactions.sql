-- name: InsertTransaction :one
INSERT INTO transactions (
    wallet_id, tx_hash, raw_tx, received_unix, block_height,
    confirmed_order, is_coinbase
) VALUES (
    sqlc.arg('wallet_id'), sqlc.arg('tx_hash'), sqlc.arg('raw_tx'),
    sqlc.arg('received_unix'), sqlc.narg('block_height')::INTEGER,
    sqlc.narg('confirmed_order')::BIGINT, sqlc.arg('is_coinbase')
)
RETURNING id;

-- name: InsertTransactionInput :exec
INSERT INTO transaction_inputs (
    spending_tx_id, input_index, prev_tx_hash, prev_output_index
) VALUES ($1, $2, $3, $4);

-- name: GetUnminedTransactionByHash :one
SELECT id, wallet_id, tx_hash, raw_tx, received_unix, block_height,
       confirmed_order, is_coinbase
FROM transactions
WHERE wallet_id = $1 AND tx_hash = $2 AND block_height IS NULL;

-- name: GetTransactionDetailsByHash :one
SELECT t.id, t.raw_tx, t.received_unix, t.block_height,
       t.confirmed_order, b.header_hash, b.block_timestamp, l.label
FROM transactions AS t
LEFT JOIN wallet_blocks AS b
    ON b.wallet_id = t.wallet_id AND b.block_height = t.block_height
LEFT JOIN transaction_labels AS l
    ON l.wallet_id = t.wallet_id AND l.tx_hash = t.tx_hash
WHERE t.wallet_id = $1 AND t.tx_hash = $2
ORDER BY t.block_height DESC NULLS FIRST, t.id DESC
LIMIT 1;

-- name: GetUnminedTransactionDetails :one
SELECT t.id, t.raw_tx, t.received_unix, t.block_height,
       t.confirmed_order, b.header_hash, b.block_timestamp, l.label
FROM transactions AS t
LEFT JOIN wallet_blocks AS b
    ON b.wallet_id = t.wallet_id AND b.block_height = t.block_height
LEFT JOIN transaction_labels AS l
    ON l.wallet_id = t.wallet_id AND l.tx_hash = t.tx_hash
WHERE t.wallet_id = $1 AND t.tx_hash = $2 AND t.block_height IS NULL
LIMIT 1;

-- name: GetMinedTransactionDetails :one
SELECT t.id, t.raw_tx, t.received_unix, t.block_height,
       t.confirmed_order, b.header_hash, b.block_timestamp, l.label
FROM transactions AS t
INNER JOIN wallet_blocks AS b
    ON b.wallet_id = t.wallet_id AND b.block_height = t.block_height
LEFT JOIN transaction_labels AS l
    ON l.wallet_id = t.wallet_id AND l.tx_hash = t.tx_hash
WHERE t.wallet_id = sqlc.arg('wallet_id')
  AND t.tx_hash = sqlc.arg('tx_hash')
  AND t.block_height = sqlc.arg('block_height')::INTEGER
  AND b.header_hash = sqlc.arg('block_hash')
LIMIT 1;

-- name: GetTransactionDetailsByID :one
SELECT t.id, t.raw_tx, t.received_unix, t.block_height,
       t.confirmed_order, b.header_hash, b.block_timestamp, l.label
FROM transactions AS t
LEFT JOIN wallet_blocks AS b
    ON b.wallet_id = t.wallet_id AND b.block_height = t.block_height
LEFT JOIN transaction_labels AS l
    ON l.wallet_id = t.wallet_id AND l.tx_hash = t.tx_hash
WHERE t.wallet_id = $1 AND t.id = $2
LIMIT 1;

-- name: NextBlockTransactionOrder :one
SELECT cast(COALESCE(MAX(confirmed_order) + 1, 0) AS BIGINT)
FROM transactions
WHERE wallet_id = $1 AND block_height = $2;

-- name: ListMinedTransactionsFromHeight :many
SELECT id, tx_hash, is_coinbase
FROM transactions
WHERE wallet_id = sqlc.arg('wallet_id')
  AND block_height >= sqlc.arg('height')::INTEGER
ORDER BY block_height DESC, confirmed_order DESC, id DESC;

-- name: DetachMinedTransaction :execrows
UPDATE transactions
SET block_height = NULL, confirmed_order = NULL
WHERE wallet_id = $1 AND id = $2 AND block_height IS NOT NULL;

-- name: DeleteCreditSpendsBySpendingTx :execrows
DELETE FROM credit_spends
WHERE wallet_id = $1 AND spending_tx_id = $2;

-- name: ListUnminedSpendersByPrevHash :many
SELECT DISTINCT spender.id, spender.tx_hash
FROM transaction_inputs AS input
INNER JOIN transactions AS spender
    ON spender.id = input.spending_tx_id
    AND spender.wallet_id = sqlc.arg('wallet_id')
WHERE spender.wallet_id = sqlc.arg('wallet_id')
  AND spender.block_height IS NULL
  AND input.prev_tx_hash = sqlc.arg('prev_tx_hash')
ORDER BY spender.id;

-- name: GetMinedTransactionByIncidence :one
SELECT t.id, t.wallet_id, t.tx_hash, t.raw_tx, t.received_unix,
       t.block_height, t.confirmed_order, t.is_coinbase
FROM transactions AS t
INNER JOIN wallet_blocks AS b
    ON b.wallet_id = t.wallet_id AND b.block_height = t.block_height
WHERE t.wallet_id = sqlc.arg('wallet_id')
  AND t.tx_hash = sqlc.arg('tx_hash')
  AND t.block_height = sqlc.arg('block_height')
  AND b.header_hash = sqlc.arg('block_hash');

-- name: ListTransactionIncidencesByHash :many
SELECT id, wallet_id, tx_hash, raw_tx, received_unix, block_height,
       confirmed_order, is_coinbase
FROM transactions
WHERE wallet_id = $1 AND tx_hash = $2
ORDER BY block_height NULLS FIRST, block_height DESC, id DESC;

-- name: ListUnminedTransactions :many
SELECT id, wallet_id, tx_hash, raw_tx, received_unix, block_height,
       confirmed_order, is_coinbase
FROM transactions
WHERE wallet_id = $1 AND block_height IS NULL
ORDER BY tx_hash;

-- name: ListMinedTransactionsForward :many
SELECT t.id, t.wallet_id, t.tx_hash, t.raw_tx, t.received_unix,
       t.block_height, t.confirmed_order, t.is_coinbase,
       b.header_hash, b.block_timestamp
FROM transactions AS t
INNER JOIN wallet_blocks AS b
    ON b.wallet_id = t.wallet_id AND b.block_height = t.block_height
WHERE t.wallet_id = sqlc.arg('wallet_id')
  AND t.block_height BETWEEN sqlc.arg('start_height')::INTEGER
                         AND sqlc.arg('end_height')::INTEGER
ORDER BY t.block_height ASC, t.confirmed_order ASC;

-- name: ListMinedTransactionsReverse :many
SELECT t.id, t.wallet_id, t.tx_hash, t.raw_tx, t.received_unix,
       t.block_height, t.confirmed_order, t.is_coinbase,
       b.header_hash, b.block_timestamp
FROM transactions AS t
INNER JOIN wallet_blocks AS b
    ON b.wallet_id = t.wallet_id AND b.block_height = t.block_height
WHERE t.wallet_id = sqlc.arg('wallet_id')
  AND t.block_height BETWEEN sqlc.arg('end_height')::INTEGER
                         AND sqlc.arg('start_height')::INTEGER
ORDER BY t.block_height DESC, t.confirmed_order ASC;

-- name: PromoteUnminedTransaction :one
UPDATE transactions
SET block_height = $1, confirmed_order = $2
WHERE wallet_id = $3 AND tx_hash = $4 AND block_height IS NULL
RETURNING id;

-- name: ListUnminedSpenders :many
SELECT t.id, t.tx_hash, i.input_index
FROM transaction_inputs AS i
INNER JOIN transactions AS t
    ON t.id = i.spending_tx_id
    AND t.wallet_id = sqlc.arg('wallet_id')
WHERE t.wallet_id = sqlc.arg('wallet_id')
  AND t.block_height IS NULL
  AND i.prev_tx_hash = sqlc.arg('prev_tx_hash')
  AND i.prev_output_index = sqlc.arg('prev_output_index')
  AND t.id <> sqlc.arg('exclude_transaction_id')
ORDER BY t.tx_hash, i.input_index;

-- name: DeleteTransactionByID :execrows
DELETE FROM transactions WHERE wallet_id = $1 AND id = $2;

-- name: PutTransactionLabel :exec
INSERT INTO transaction_labels (wallet_id, tx_hash, label)
VALUES ($1, $2, $3)
ON CONFLICT (wallet_id, tx_hash) DO UPDATE SET label = excluded.label;

-- name: GetTransactionLabel :one
SELECT label FROM transaction_labels WHERE wallet_id = $1 AND tx_hash = $2;

-- name: GetMinedTransactionID :one
SELECT t.id
FROM transactions AS t
INNER JOIN wallet_blocks AS b
    ON b.wallet_id = t.wallet_id AND b.block_height = t.block_height
WHERE t.wallet_id = sqlc.arg('wallet_id')
  AND t.tx_hash = sqlc.arg('tx_hash')
  AND t.block_height = sqlc.arg('block_height')::INTEGER
  AND b.header_hash = sqlc.arg('block_hash');
