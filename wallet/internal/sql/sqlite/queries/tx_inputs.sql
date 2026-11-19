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

-- name: GetWalletCreditByOutpoint :one
-- Credit replay checks immutable ownership even after a credit has been spent.
-- Availability belongs to the input relation, not this ownership lookup.
SELECT a.script_pub_key
FROM transactions AS t
INNER JOIN utxos AS u ON t.id = u.tx_id
INNER JOIN addresses AS a ON u.address_id = a.id AND t.wallet_id = a.wallet_id
WHERE
    t.wallet_id = sqlc.arg('wallet_id') AND t.tx_hash = sqlc.arg('tx_hash')
    AND u.output_index = sqlc.arg('output_index');

-- name: ListConflictingTransactions :many
-- Lists unconfirmed transactions that share an input with this transaction.
-- Parent credits need not be known: the lookup matches retained prevouts.
SELECT DISTINCT
    peer.id,
    peer.tx_hash
FROM transactions AS t
INNER JOIN tx_inputs AS claim ON t.wallet_id = claim.wallet_id AND t.id = claim.tx_id
INNER JOIN tx_inputs AS other
    ON
        claim.wallet_id = other.wallet_id AND claim.prev_tx_hash = other.prev_tx_hash
        AND claim.prev_output_index = other.prev_output_index AND claim.tx_id != other.tx_id
INNER JOIN transactions AS peer ON other.wallet_id = peer.wallet_id AND other.tx_id = peer.id
WHERE
    t.wallet_id = sqlc.arg('wallet_id') AND t.tx_hash = sqlc.arg('tx_hash')
    AND peer.block_height IS NULL AND peer.tx_status IN (0, 1)
ORDER BY peer.id;

-- name: GetTxInputValidity :one
-- Check recorded inputs for invalid known parents or a confirmed competitor.
-- An unknown parent is allowed; its credit need not be discovered first.
SELECT
    cast(EXISTS (
        SELECT 1 FROM tx_inputs AS claim
        INNER JOIN transactions AS parent
            ON claim.wallet_id = parent.wallet_id AND claim.prev_tx_hash = parent.tx_hash
        WHERE
            claim.wallet_id = t.wallet_id AND claim.tx_id = t.id
            AND NOT EXISTS (
                SELECT 1 FROM eligible_transactions AS eligible
                WHERE eligible.wallet_id = parent.wallet_id AND eligible.id = parent.id
            )
    ) AS BOOLEAN) AS has_invalid_parent,
    cast(EXISTS (
        SELECT 1 FROM tx_inputs AS claim
        INNER JOIN tx_inputs AS other
            ON
                claim.wallet_id = other.wallet_id AND claim.prev_tx_hash = other.prev_tx_hash
                AND claim.prev_output_index = other.prev_output_index AND claim.tx_id != other.tx_id
        INNER JOIN transactions AS peer ON other.wallet_id = peer.wallet_id AND other.tx_id = peer.id
        WHERE claim.wallet_id = t.wallet_id AND claim.tx_id = t.id AND peer.block_height IS NOT NULL
    ) AS BOOLEAN) AS has_confirmed_conflict
FROM transactions AS t
WHERE t.wallet_id = sqlc.arg('wallet_id') AND t.tx_hash = sqlc.arg('tx_hash');

-- name: HasTxGraphStateChange :one
-- Report whether the requested status/block change involves terminal history
-- or competing input claims, so UpdateTx can reject it before writing metadata.
SELECT cast(EXISTS (
    SELECT 1 FROM transactions AS t
    WHERE
        t.wallet_id = sqlc.arg('wallet_id') AND t.tx_hash = sqlc.arg('tx_hash')
        AND (
            t.tx_status NOT IN (0, 1)
            OR (
                (t.block_height IS NULL) != (cast(sqlc.narg('block_height') AS INTEGER) IS NULL)
                AND EXISTS (
                    SELECT 1 FROM tx_inputs AS claim
                    INNER JOIN tx_inputs AS other
                        ON
                            claim.wallet_id = other.wallet_id AND claim.prev_tx_hash = other.prev_tx_hash
                            AND claim.prev_output_index = other.prev_output_index AND claim.tx_id != other.tx_id
                    WHERE claim.wallet_id = t.wallet_id AND claim.tx_id = t.id
                )
            )
        )
) AS BOOLEAN) AS requires_reconciliation;
