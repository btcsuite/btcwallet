-- name: AcquireOutputLease :execrows
INSERT INTO utxo_leases (
    wallet_id, tx_hash, output_index, lock_id, expires_unix
) VALUES (
    sqlc.arg('wallet_id'), sqlc.arg('tx_hash'), sqlc.arg('output_index'),
    sqlc.arg('lock_id'),
    -- Referencing now_unix here keeps sqlc's SQLite parameter numbering
    -- distinct from expires_unix in the conflict predicate below.
    cast(CASE
        WHEN cast(sqlc.arg('now_unix') AS INTEGER) IS NULL
        THEN sqlc.arg('expires_unix')
        ELSE sqlc.arg('expires_unix')
    END AS INTEGER)
)
ON CONFLICT (wallet_id, tx_hash, output_index) DO UPDATE SET
    lock_id = excluded.lock_id,
    expires_unix = excluded.expires_unix
WHERE utxo_leases.lock_id = excluded.lock_id
   OR utxo_leases.expires_unix <= ?5;

-- name: GetOutputLease :one
SELECT wallet_id, tx_hash, output_index, lock_id, expires_unix
FROM utxo_leases
WHERE wallet_id = ? AND tx_hash = ? AND output_index = ?;

-- name: ListActiveOutputLeases :many
SELECT wallet_id, tx_hash, output_index, lock_id, expires_unix
FROM utxo_leases
WHERE wallet_id = ? AND expires_unix > ?
ORDER BY tx_hash, output_index;

-- name: DeleteOutputLease :execrows
DELETE FROM utxo_leases
WHERE wallet_id = ? AND tx_hash = ? AND output_index = ? AND lock_id = ?;

-- name: DeleteExpiredOutputLeases :execrows
DELETE FROM utxo_leases WHERE wallet_id = ? AND expires_unix <= ?;

-- name: DeleteOutputLeaseAnyOwner :execrows
DELETE FROM utxo_leases
WHERE wallet_id = ? AND tx_hash = ? AND output_index = ?;
