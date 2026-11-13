-- name: InsertTxInput :exec
-- Retain immutable prevout facts independently of wallet credit discovery.
-- Replaying the same input position preserves the existing indexed fact.
INSERT INTO tx_inputs (
    wallet_id, tx_id, input_index, prev_tx_hash, prev_output_index
) VALUES (
    sqlc.arg('wallet_id'), sqlc.arg('tx_id'), sqlc.arg('input_index'),
    sqlc.arg('prev_tx_hash'), sqlc.arg('prev_output_index')
)
ON CONFLICT (wallet_id, tx_id, input_index) DO NOTHING;

-- name: ListTransactionsMissingInputs :many
-- Startup reconstructs missing input facts from every retained transaction.
-- Atomic input writes make absence sufficient; coinbase has no ordinary input.
SELECT
    t.id,
    t.raw_tx
FROM transactions AS t
WHERE
    t.wallet_id = sqlc.arg('wallet_id')
    AND NOT t.is_coinbase
    AND NOT EXISTS (
        SELECT 1 FROM tx_inputs AS i
        WHERE i.wallet_id = t.wallet_id AND i.tx_id = t.id
    )
ORDER BY t.id;
