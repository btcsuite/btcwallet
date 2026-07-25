-- name: InsertCredit :one
INSERT INTO credits (
    wallet_id, transaction_id, output_index, amount, pk_script, is_change,
    address_scope_id, address_id
) VALUES (
    sqlc.arg('wallet_id'), sqlc.arg('transaction_id'),
    sqlc.arg('output_index'), sqlc.arg('amount'), sqlc.arg('pk_script'),
    sqlc.arg('is_change'),
    cast(sqlc.narg('address_scope_id') AS INTEGER),
    sqlc.narg('address_id')
)
RETURNING id;

-- name: SetActiveCreditIncidence :exec
INSERT INTO active_credit_incidences (
    wallet_id, tx_hash, output_index, credit_id
)
SELECT c.wallet_id, funding.tx_hash, c.output_index, c.id
FROM credits AS c
INNER JOIN transactions AS funding
    ON funding.wallet_id = c.wallet_id AND funding.id = c.transaction_id
WHERE c.wallet_id = ? AND c.id = ?
ON CONFLICT (wallet_id, tx_hash, output_index) DO UPDATE SET
    credit_id = excluded.credit_id;

-- name: RecordCreditSpend :execrows
INSERT INTO credit_spends (
    wallet_id, credit_id, spending_tx_id, input_index
)
SELECT c.wallet_id, c.id, i.spending_tx_id, i.input_index
FROM credits AS c
INNER JOIN transactions AS funding
    ON funding.wallet_id = c.wallet_id AND funding.id = c.transaction_id
INNER JOIN transaction_inputs AS i
    ON i.prev_tx_hash = funding.tx_hash
    AND i.prev_output_index = c.output_index
INNER JOIN transactions AS spender
    ON spender.wallet_id = c.wallet_id AND spender.id = i.spending_tx_id
WHERE c.wallet_id = ?
  AND c.id = ?
  AND i.spending_tx_id = ?
  AND i.input_index = ?
  AND spender.wallet_id = c.wallet_id
  AND spender.block_height IS NOT NULL
ON CONFLICT (credit_id) DO UPDATE SET
    spending_tx_id = excluded.spending_tx_id,
    input_index = excluded.input_index;

-- name: DeleteCreditSpend :execrows
DELETE FROM credit_spends
WHERE wallet_id = ? AND credit_id = ?
  AND spending_tx_id = ? AND input_index = ?;

-- name: GetCredit :one
SELECT id, wallet_id, transaction_id, output_index, amount, pk_script,
       is_change, address_scope_id, address_id
FROM credits
WHERE wallet_id = ? AND transaction_id = ? AND output_index = ?;

-- name: ListTransactionCredits :many
SELECT c.id, c.output_index, c.amount, c.pk_script, c.is_change,
       c.address_scope_id, c.address_id,
       EXISTS (
           SELECT 1
           FROM credit_spends AS spend
           WHERE spend.wallet_id = c.wallet_id AND spend.credit_id = c.id
       ) OR EXISTS (
           SELECT 1
           FROM transaction_inputs AS input
           INNER JOIN transactions AS spender
               ON spender.wallet_id = c.wallet_id
               AND spender.id = input.spending_tx_id
           INNER JOIN transactions AS funding
               ON funding.wallet_id = c.wallet_id
               AND funding.id = c.transaction_id
           WHERE spender.wallet_id = c.wallet_id
             AND spender.block_height IS NULL
             AND input.prev_tx_hash = funding.tx_hash
             AND input.prev_output_index = c.output_index
       ) AS is_spent
FROM credits AS c
WHERE c.wallet_id = ? AND c.transaction_id = ?
ORDER BY c.output_index;

-- name: ListUnspentCredits :many
WITH query_params AS (
    SELECT cast(sqlc.arg('now_unix') AS INTEGER) AS now_unix
)
SELECT c.id, funding.tx_hash, c.output_index, c.amount, c.pk_script,
       c.is_change, funding.received_unix, funding.block_height,
       funding.is_coinbase, c.address_scope_id, c.address_id,
       block.header_hash, block.block_timestamp
FROM credits AS c
INNER JOIN transactions AS funding
    ON funding.wallet_id = c.wallet_id AND funding.id = c.transaction_id
INNER JOIN active_credit_incidences AS active
    ON active.wallet_id = c.wallet_id AND active.credit_id = c.id
LEFT JOIN wallet_blocks AS block
    ON block.wallet_id = funding.wallet_id
    AND block.block_height = funding.block_height
INNER JOIN query_params
WHERE c.wallet_id = sqlc.arg('wallet_id')
  AND NOT EXISTS (
      SELECT 1 FROM credit_spends AS spend
      WHERE spend.wallet_id = c.wallet_id AND spend.credit_id = c.id
  )
  AND NOT EXISTS (
      SELECT 1
      FROM transaction_inputs AS i
      INNER JOIN transactions AS spender
          ON spender.wallet_id = c.wallet_id
          AND spender.id = i.spending_tx_id
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
        AND l.expires_unix > query_params.now_unix
  )
ORDER BY funding.tx_hash, c.output_index;

-- name: ListOutputsToWatch :many
SELECT funding.tx_hash, c.output_index, c.pk_script
FROM credits AS c
INNER JOIN transactions AS funding
    ON funding.wallet_id = c.wallet_id AND funding.id = c.transaction_id
INNER JOIN active_credit_incidences AS active
    ON active.wallet_id = c.wallet_id AND active.credit_id = c.id
WHERE c.wallet_id = sqlc.arg('wallet_id')
  AND NOT EXISTS (
      SELECT 1
      FROM credit_spends AS spend
      WHERE spend.wallet_id = c.wallet_id AND spend.credit_id = c.id
  )
ORDER BY funding.tx_hash, c.output_index;

-- name: ListTransactionDebits :many
SELECT debit.input_index, debit.amount
FROM (
    SELECT spend.input_index, credit.amount
    FROM credit_spends AS spend
    INNER JOIN credits AS credit
        ON credit.wallet_id = spend.wallet_id AND credit.id = spend.credit_id
    WHERE spend.wallet_id = sqlc.arg('wallet_id')
      AND spend.spending_tx_id = sqlc.arg('transaction_id')

    UNION ALL

    SELECT input.input_index, credit.amount
    FROM transactions AS spender
    INNER JOIN transaction_inputs AS input
        ON input.spending_tx_id = spender.id
    INNER JOIN active_credit_incidences AS active
        ON active.wallet_id = spender.wallet_id
        AND active.tx_hash = input.prev_tx_hash
        AND active.output_index = input.prev_output_index
    INNER JOIN credits AS credit
        ON credit.wallet_id = active.wallet_id AND credit.id = active.credit_id
    WHERE spender.wallet_id = sqlc.arg('wallet_id')
      AND spender.id = sqlc.arg('transaction_id')
      AND spender.block_height IS NULL
) AS debit
ORDER BY debit.input_index;

-- name: GetActiveCreditID :one
SELECT credit.id
FROM active_credit_incidences AS active
INNER JOIN credits AS credit
    ON credit.wallet_id = active.wallet_id AND credit.id = active.credit_id
WHERE active.wallet_id = ? AND active.tx_hash = ?
  AND active.output_index = ?;

-- name: IsKnownOutput :one
SELECT EXISTS (
    SELECT 1
    FROM active_credit_incidences AS active
    INNER JOIN credits AS credit
        ON credit.wallet_id = active.wallet_id AND credit.id = active.credit_id
    WHERE active.wallet_id = ? AND active.tx_hash = ?
      AND active.output_index = ?
      AND NOT EXISTS (
          SELECT 1 FROM credit_spends AS spend
          WHERE spend.wallet_id = credit.wallet_id
            AND spend.credit_id = credit.id
      )
);

-- name: GetUnminedPreviousPkScript :one
SELECT credit.pk_script
FROM active_credit_incidences AS active
INNER JOIN credits AS credit
    ON credit.wallet_id = active.wallet_id AND credit.id = active.credit_id
WHERE active.wallet_id = ? AND active.tx_hash = ?
  AND active.output_index = ?
  AND NOT EXISTS (
      SELECT 1 FROM credit_spends AS spend
      WHERE spend.wallet_id = credit.wallet_id
        AND spend.credit_id = credit.id
  );

-- name: GetMinedPreviousPkScript :one
SELECT credit.pk_script
FROM credit_spends AS spend
INNER JOIN credits AS credit
    ON credit.wallet_id = spend.wallet_id AND credit.id = spend.credit_id
WHERE spend.wallet_id = ? AND spend.spending_tx_id = ?
  AND spend.input_index = ?;
