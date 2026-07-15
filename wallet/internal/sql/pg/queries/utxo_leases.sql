-- name: AcquireOutputLease :execrows
INSERT INTO utxo_leases (
    wallet_id, tx_hash, output_index, lock_id, expires_unix
) VALUES (
    sqlc.arg('wallet_id'), sqlc.arg('tx_hash'), sqlc.arg('output_index'),
    sqlc.arg('lock_id'), sqlc.arg('expires_unix')
)
ON CONFLICT (wallet_id, tx_hash, output_index) DO UPDATE SET
    lock_id = excluded.lock_id,
    expires_unix = excluded.expires_unix
WHERE utxo_leases.lock_id = excluded.lock_id
   OR utxo_leases.expires_unix <= sqlc.arg('now_unix');

-- name: GetOutputLease :one
SELECT wallet_id, tx_hash, output_index, lock_id, expires_unix
FROM utxo_leases
WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3;

-- name: ListActiveOutputLeases :many
SELECT wallet_id, tx_hash, output_index, lock_id, expires_unix
FROM utxo_leases
WHERE wallet_id = $1 AND expires_unix > $2
ORDER BY tx_hash, output_index;

-- name: DeleteOutputLease :execrows
DELETE FROM utxo_leases
WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3 AND lock_id = $4;

-- name: DeleteExpiredOutputLeases :execrows
DELETE FROM utxo_leases WHERE wallet_id = $1 AND expires_unix <= $2;

-- name: DeleteOutputLeaseAnyOwner :execrows
DELETE FROM utxo_leases
WHERE wallet_id = $1 AND tx_hash = $2 AND output_index = $3;
