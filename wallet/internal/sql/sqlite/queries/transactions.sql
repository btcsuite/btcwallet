-- name: InsertTransaction :one
INSERT INTO transactions (
    wallet_id, tx_hash, raw_tx, received_unix, block_height,
    confirmed_order, is_coinbase
) VALUES (
    sqlc.arg('wallet_id'), sqlc.arg('tx_hash'), sqlc.arg('raw_tx'),
    sqlc.arg('received_unix'),
    cast(sqlc.narg('block_height') AS INTEGER),
    cast(sqlc.narg('confirmed_order') AS INTEGER),
    sqlc.arg('is_coinbase')
)
RETURNING id;

-- name: InsertTransactionInput :exec
INSERT INTO transaction_inputs (
    spending_tx_id, input_index, prev_tx_hash, prev_output_index
) VALUES (?, ?, ?, ?);

-- name: GetUnminedTransactionByHash :one
SELECT id, wallet_id, tx_hash, raw_tx, received_unix, block_height,
       confirmed_order, is_coinbase
FROM transactions
WHERE wallet_id = ? AND tx_hash = ? AND block_height IS NULL;

-- name: ListMinedTransactionsFromHeight :many
SELECT id, tx_hash, is_coinbase
FROM transactions
WHERE wallet_id = sqlc.arg('wallet_id')
  AND block_height >= cast(sqlc.arg('height') AS INTEGER)
ORDER BY block_height DESC, confirmed_order DESC, id DESC;

-- name: DetachMinedTransaction :execrows
UPDATE transactions
SET block_height = NULL, confirmed_order = NULL
WHERE wallet_id = ? AND id = ? AND block_height IS NOT NULL;

-- name: DeleteCreditSpendsBySpendingTx :execrows
DELETE FROM credit_spends
WHERE wallet_id = ? AND spending_tx_id = ?;

-- name: ListUnminedSpendersByPrevHash :many
SELECT DISTINCT spender.id, spender.tx_hash
FROM transaction_inputs AS input
INNER JOIN transactions AS spender ON spender.id = input.spending_tx_id
WHERE spender.wallet_id = sqlc.arg('wallet_id')
  AND spender.block_height IS NULL
  AND input.prev_tx_hash = sqlc.arg('prev_tx_hash')
ORDER BY spender.id;

-- name: GetMinedTransactionByIncidence :one
SELECT t.id, t.wallet_id, t.tx_hash, t.raw_tx, t.received_unix,
       t.block_height, t.confirmed_order, t.is_coinbase
FROM transactions AS t
INNER JOIN blocks AS b ON b.block_height = t.block_height
WHERE t.wallet_id = sqlc.arg('wallet_id')
  AND t.tx_hash = sqlc.arg('tx_hash')
  AND t.block_height = sqlc.arg('block_height')
  AND b.header_hash = sqlc.arg('block_hash');

-- name: ListTransactionIncidencesByHash :many
SELECT id, wallet_id, tx_hash, raw_tx, received_unix, block_height,
       confirmed_order, is_coinbase
FROM transactions
WHERE wallet_id = ? AND tx_hash = ?
ORDER BY block_height IS NOT NULL, block_height DESC, id DESC;

-- name: ListUnminedTransactions :many
SELECT id, wallet_id, tx_hash, raw_tx, received_unix, block_height,
       confirmed_order, is_coinbase
FROM transactions
WHERE wallet_id = ? AND block_height IS NULL
ORDER BY tx_hash;

-- name: ListMinedTransactionsForward :many
SELECT t.id, t.wallet_id, t.tx_hash, t.raw_tx, t.received_unix,
       t.block_height, t.confirmed_order, t.is_coinbase,
       b.header_hash, b.block_timestamp
FROM transactions AS t
INNER JOIN blocks AS b ON b.block_height = t.block_height
WHERE t.wallet_id = sqlc.arg('wallet_id')
  AND t.block_height BETWEEN cast(sqlc.arg('start_height') AS INTEGER)
                         AND cast(sqlc.arg('end_height') AS INTEGER)
ORDER BY t.block_height ASC, t.confirmed_order ASC;

-- name: ListMinedTransactionsReverse :many
SELECT t.id, t.wallet_id, t.tx_hash, t.raw_tx, t.received_unix,
       t.block_height, t.confirmed_order, t.is_coinbase,
       b.header_hash, b.block_timestamp
FROM transactions AS t
INNER JOIN blocks AS b ON b.block_height = t.block_height
WHERE t.wallet_id = sqlc.arg('wallet_id')
  AND t.block_height BETWEEN cast(sqlc.arg('end_height') AS INTEGER)
                         AND cast(sqlc.arg('start_height') AS INTEGER)
ORDER BY t.block_height DESC, t.confirmed_order ASC;

-- name: PromoteUnminedTransaction :execrows
UPDATE transactions
SET block_height = ?, confirmed_order = ?
WHERE wallet_id = ? AND tx_hash = ? AND block_height IS NULL;

-- name: ListUnminedSpenders :many
SELECT t.id, t.tx_hash, i.input_index
FROM transaction_inputs AS i
INNER JOIN transactions AS t ON t.id = i.spending_tx_id
WHERE t.wallet_id = sqlc.arg('wallet_id')
  AND t.block_height IS NULL
  AND i.prev_tx_hash = sqlc.arg('prev_tx_hash')
  AND i.prev_output_index = sqlc.arg('prev_output_index')
ORDER BY t.tx_hash, i.input_index;

-- name: DeleteTransactionByID :execrows
DELETE FROM transactions WHERE wallet_id = ? AND id = ?;

-- name: PutTransactionLabel :exec
INSERT INTO transaction_labels (wallet_id, tx_hash, label)
VALUES (?, ?, ?)
ON CONFLICT (wallet_id, tx_hash) DO UPDATE SET label = excluded.label;

-- name: GetTransactionLabel :one
SELECT label FROM transaction_labels WHERE wallet_id = ? AND tx_hash = ?;
