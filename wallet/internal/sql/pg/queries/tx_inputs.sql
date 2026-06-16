-- name: InsertTxInput :execrows
-- Records the previous outpoint spent by one input of a wallet-scoped
-- transaction.
--
-- How:
-- - Writes directly to tx_inputs using the already-resolved spending
--   transaction ID plus the input's previous outpoint.
-- - Stores every input, including inputs that spend outpoints the wallet does
--   not own, so conflict discovery can match shared external inputs.
-- - Uses an explicit conflict target so confirm-reuse replays of the same input
--   are ignored without masking other constraint failures.
-- Performance:
-- - Single-row insert with cheap duplicate suppression via `ON CONFLICT`.
INSERT INTO tx_inputs (
    wallet_id,
    tx_id,
    input_index,
    prev_tx_hash,
    prev_output_index
) VALUES (
    $1, $2, $3, $4, $5
)
ON CONFLICT (tx_id, input_index) DO NOTHING;

-- name: ListActiveUnminedInputSpenders :many
-- Lists the active unmined wallet transactions that spend a given previous
-- outpoint.
--
-- How:
-- - Matches input rows on the wallet-scoped previous outpoint lookup index.
-- - Joins transactions on the wallet-scoped `(wallet_id, id)` key and keeps
--   only spenders whose transaction is still in the active unmined set
--   (`block_height IS NULL` and `pending`/`published` status). The status
--   predicate stays in the query because the spending transaction's status
--   lives on transactions, not on the input row.
-- - Returns distinct spender transaction IDs so a transaction that spends the
--   same outpoint through more than one input is reported once.
-- Performance:
-- - Uses the `(wallet_id, prev_tx_hash, prev_output_index)` index to bound the
--   scan to the matching previous outpoint, then the live-only transaction
--   index for the status filter.
SELECT DISTINCT i.tx_id
FROM tx_inputs AS i
INNER JOIN transactions AS t
    ON i.wallet_id = t.wallet_id AND i.tx_id = t.id
WHERE
    i.wallet_id = $1
    AND i.prev_tx_hash = $2
    AND i.prev_output_index = $3
    AND t.block_height IS NULL
    AND t.tx_status IN (0, 1);
