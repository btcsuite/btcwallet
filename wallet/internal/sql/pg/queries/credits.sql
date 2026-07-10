-- name: InsertCredit :one
INSERT INTO credits (
    wallet_id, transaction_id, output_index, amount, pk_script, is_change,
    address_scope_id, address_id
) VALUES (
    sqlc.arg('wallet_id'), sqlc.arg('transaction_id'),
    sqlc.arg('output_index'), sqlc.arg('amount'), sqlc.arg('pk_script'),
    sqlc.arg('is_change'), sqlc.narg('address_scope_id')::BIGINT,
    sqlc.narg('address_id')::BYTEA
)
RETURNING id;

-- name: SetActiveCreditIncidence :exec
INSERT INTO active_credit_incidences (
    wallet_id, tx_hash, output_index, credit_id
)
SELECT c.wallet_id, funding.tx_hash, c.output_index, c.id
FROM credits AS c
INNER JOIN transactions AS funding ON funding.id = c.transaction_id
WHERE c.wallet_id = $1 AND c.id = $2
ON CONFLICT (wallet_id, tx_hash, output_index) DO UPDATE SET
    credit_id = excluded.credit_id;

-- name: RecordCreditSpend :execrows
INSERT INTO credit_spends (
    wallet_id, credit_id, spending_tx_id, input_index
)
SELECT c.wallet_id, c.id, i.spending_tx_id, i.input_index
FROM credits AS c
INNER JOIN transactions AS funding ON funding.id = c.transaction_id
INNER JOIN transaction_inputs AS i
    ON i.prev_tx_hash = funding.tx_hash
    AND i.prev_output_index = c.output_index
INNER JOIN transactions AS spender ON spender.id = i.spending_tx_id
WHERE c.wallet_id = $1
  AND c.id = $2
  AND i.spending_tx_id = $3
  AND i.input_index = $4
  AND spender.wallet_id = c.wallet_id
  AND spender.block_height IS NOT NULL
ON CONFLICT (credit_id) DO UPDATE SET
    spending_tx_id = excluded.spending_tx_id,
    input_index = excluded.input_index;

-- name: DeleteCreditSpend :execrows
DELETE FROM credit_spends
WHERE wallet_id = $1 AND credit_id = $2
  AND spending_tx_id = $3 AND input_index = $4;

-- name: GetCredit :one
SELECT id, wallet_id, transaction_id, output_index, amount, pk_script,
       is_change, address_scope_id, address_id
FROM credits
WHERE transaction_id = $1 AND output_index = $2;

-- name: ListTransactionCredits :many
SELECT c.id, c.output_index, c.amount, c.pk_script, c.is_change,
       c.address_scope_id, c.address_id,
       EXISTS (
           SELECT 1
           FROM credit_spends AS spend
           WHERE spend.credit_id = c.id
       ) AS is_spent
FROM credits AS c
WHERE c.wallet_id = $1 AND c.transaction_id = $2
ORDER BY c.output_index;

-- name: ListUnspentCredits :many
SELECT c.id, funding.tx_hash, c.output_index, c.amount, c.pk_script,
       c.is_change, funding.received_unix, funding.block_height,
       funding.is_coinbase, c.address_scope_id, c.address_id
FROM credits AS c
INNER JOIN transactions AS funding ON funding.id = c.transaction_id
INNER JOIN active_credit_incidences AS active ON active.credit_id = c.id
WHERE c.wallet_id = sqlc.arg('wallet_id')
  AND NOT EXISTS (
      SELECT 1 FROM credit_spends AS spend WHERE spend.credit_id = c.id
  )
  AND NOT EXISTS (
      SELECT 1
      FROM transaction_inputs AS i
      INNER JOIN transactions AS spender ON spender.id = i.spending_tx_id
      WHERE spender.wallet_id = c.wallet_id
        AND spender.block_height IS NULL
        AND i.prev_tx_hash = funding.tx_hash
        AND i.prev_output_index = c.output_index
  )
  AND NOT EXISTS (
      SELECT 1
      FROM utxo_leases AS l
      WHERE l.wallet_id = c.wallet_id
        AND l.tx_hash = funding.tx_hash
        AND l.output_index = c.output_index
        AND l.expires_unix > sqlc.arg('now_unix')::BIGINT
  )
ORDER BY funding.tx_hash, c.output_index;

-- name: ListOutputsToWatch :many
SELECT funding.tx_hash, c.output_index, c.pk_script
FROM credits AS c
INNER JOIN transactions AS funding ON funding.id = c.transaction_id
INNER JOIN active_credit_incidences AS active ON active.credit_id = c.id
WHERE c.wallet_id = sqlc.arg('wallet_id')
  AND NOT EXISTS (
      SELECT 1
      FROM credit_spends AS spend
      WHERE spend.credit_id = c.id
  )
ORDER BY funding.tx_hash, c.output_index;
