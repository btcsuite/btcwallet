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
