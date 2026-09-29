-- name: AcquireUtxoLease :one
-- Acquires or renews a lease for an outpoint and returns the resulting
-- expiration time and spend policy.
--
-- How:
-- - Resolves the outpoint to a current UTXO row and writes the lease in the
--   same statement.
-- - Rechecks that the outpoint is still unspent and its parent transaction is
--   still in `pending` or `published` status at write time.
-- - Uses one `INSERT .. ON CONFLICT DO UPDATE` statement so creation, renewal,
--   and expired-lease takeover all happen atomically.
-- Lease semantics:
-- - If the UTXO has no lease row, insert a new lease.
-- - If the UTXO has an expired timed lease, steal it.
-- - If the UTXO has an active lease with the same lock_id, renew it.
-- - If the UTXO has an active lease with a different lock_id, return no
--   rows (caller should treat this as "already leased").
-- - A confirmation-controlled lease (release_after_spend_confs > 0) never
--   expires by wall clock, so only its owner can renew it.
-- - A renewal with zero release_after_spend_confs keeps the stored depth.
--
-- NOTE: expires_at is computed by the caller as time.Now().UTC()+duration, and
-- callers must also pass a UTC-normalized now_utc for lease-expiry checks.
-- Performance:
-- - SQLite executes the resolution and lease write atomically inside one
--   statement, which avoids stale-ID races between separate helper calls.
INSERT INTO utxo_leases (
    wallet_id,
    utxo_id,
    lock_id,
    expires_at,
    release_after_spend_confs
)
SELECT
    sqlc.arg('wallet_id') AS wallet_id,
    u.id AS utxo_id,
    sqlc.arg('lock_id') AS lock_id,
    sqlc.arg('expires_at') AS expires_at,
    sqlc.arg('release_after_spend_confs') AS release_after_spend_confs
FROM utxos AS u
INNER JOIN transactions AS t
    ON u.tx_id = t.id
WHERE
    t.wallet_id = sqlc.arg('wallet_id')
    AND t.tx_hash = sqlc.arg('tx_hash')
    AND u.output_index = sqlc.arg('output_index')
    AND u.spent_by_tx_id IS NULL
    AND t.tx_status IN (0, 1)
    AND sqlc.arg('now_utc') IS NOT NULL
ON CONFLICT (utxo_id) DO UPDATE
SET
    lock_id = excluded.lock_id,
    expires_at = excluded.expires_at,
    release_after_spend_confs = CASE
        WHEN excluded.release_after_spend_confs = 0
            THEN utxo_leases.release_after_spend_confs
        ELSE excluded.release_after_spend_confs
    END
WHERE
utxo_leases.wallet_id = excluded.wallet_id
AND (
    -- ?7 is the generated bind slot for now_utc; sqlc leaves a literal
    -- sqlc.arg('now_utc') here, so this predicate must stay aligned with
    -- the arg ordering above.
    (
        utxo_leases.release_after_spend_confs = 0
        AND utxo_leases.expires_at <= ?7
    )
    OR utxo_leases.lock_id = excluded.lock_id
)
RETURNING expires_at, release_after_spend_confs, spend_disconnected;

-- name: ReleaseUtxoLease :execrows
-- Releases a lease for a UTXO ID if the lock_id matches.
--
-- How:
-- - Deletes by wallet, utxo ID, and lock ID so one caller cannot release
--   another caller's active lease accidentally.
-- Performance:
-- - Targets at most one row through the unique lease key.
DELETE FROM utxo_leases
WHERE
    utxo_leases.wallet_id = ?1
    AND utxo_leases.utxo_id = ?2
    AND utxo_leases.lock_id = ?3;

-- name: GetActiveUtxoLeaseLockID :one
-- Returns the lock ID for the current active lease on a UTXO ID.
--
-- How:
-- - Reads only active lease rows so callers can distinguish an active lock-ID
--   mismatch from an already-unlocked output. A confirmation-controlled lease
--   stays active until spend maturity or release.
-- Performance:
-- - Targets at most one row through the unique lease key.
SELECT lock_id
FROM utxo_leases
WHERE
    wallet_id = ?1
    AND utxo_id = ?2
    AND (
        release_after_spend_confs > 0
        OR expires_at > sqlc.arg('now_utc')
    );

-- name: ListActiveUtxoLeases :many
-- Lists all currently active leases for a wallet.
--
-- How:
-- - Starts from utxo_leases, then joins utxos and transactions so the result
--   can be returned as network outpoints.
-- - Timed rows require an unexpired lease (against the caller-supplied UTC
--   timestamp), an unspent output, and a parent transaction still in
--   `pending` or `published` status.
-- - Confirmation-controlled rows stay listed until spend maturity or release,
--   even after their output is spent or its parent is invalidated.
-- - LEFT JOINs the spending transaction to report its confirmed height, which
--   is NULL while the spend is unconfirmed or the output is unspent.
-- Performance:
-- - Restricts first by wallet and expiration, then joins only the surviving
--   lease rows back to utxos/transactions.
SELECT
    t.tx_hash,
    u.output_index,
    l.lock_id,
    l.expires_at,
    l.release_after_spend_confs,
    l.spend_disconnected,
    spend.block_height AS spend_height
FROM utxo_leases AS l
INNER JOIN utxos AS u ON l.utxo_id = u.id
INNER JOIN transactions AS t ON u.tx_id = t.id
LEFT JOIN transactions AS spend ON u.spent_by_tx_id = spend.id
WHERE
    l.wallet_id = ?1
    AND (
        l.release_after_spend_confs > 0
        OR (
            l.expires_at > sqlc.arg('now_utc')
            AND u.spent_by_tx_id IS NULL
            AND t.tx_status IN (0, 1)
        )
    )
ORDER BY l.expires_at;

-- name: DeleteExpiredUtxoLeases :execrows
-- Deletes all expired lease rows for a wallet.
--
-- How:
-- - Removes only timed rows whose expiration has passed, leaving active and
--   confirmation-controlled leases untouched.
-- Performance:
-- - Uses the expiration predicate together with wallet scoping to bound the
--   cleanup pass.
DELETE FROM utxo_leases
WHERE
    wallet_id = ?1
    AND release_after_spend_confs = 0
    AND expires_at <= sqlc.arg('now_utc');

-- name: GetReleasableUtxoIDByOutpoint :one
-- Retrieves the database ID of a UTXO whose lease can be released.
--
-- How:
-- - Resolves the outpoint like GetUtxoIDByOutpoint.
-- - Accepts an unspent output whose parent transaction is still in `pending`
--   or `published` status, or any output held by a confirmation-controlled
--   lease so its owner can release it after a spend or invalidation.
-- Performance:
-- - Uses the wallet-scoped transaction hash lookup first, then narrows to the
--   unique `(tx_id, output_index)` outpoint and its unique lease key.
SELECT u.id
FROM transactions AS t
INNER JOIN utxos AS u ON t.id = u.tx_id
INNER JOIN addresses AS a ON u.address_id = a.id
LEFT JOIN utxo_leases AS l ON u.id = l.utxo_id
WHERE
    t.wallet_id = ?1
    AND a.wallet_id = ?1
    AND t.tx_hash = ?2
    AND u.output_index = ?3
    AND (
        l.release_after_spend_confs > 0
        OR (
            t.tx_status IN (0, 1)
            AND u.spent_by_tx_id IS NULL
        )
    );

-- name: DeleteMaturedUtxoLeases :execrows
-- Deletes confirmation-controlled leases whose spend reached its release
-- depth at the wallet's stored sync tip.
--
-- How:
-- - A spend confirmed at height h has synced_height - h + 1 confirmations,
--   where h is the block height of the transaction spending the leased output.
-- - Timed leases are skipped. An unspent output, an unconfirmed spend, or a
--   wallet without a sync tip makes the comparison NULL, so the row stays.
-- Performance:
-- - Scans the wallet's leases through the wallet-scoped lease index and looks
--   up each spender by primary key.
DELETE FROM utxo_leases
WHERE
    utxo_leases.wallet_id = ?1
    AND utxo_leases.release_after_spend_confs > 0
    AND (
        SELECT s.synced_height
        FROM wallet_sync_states AS s
        WHERE s.wallet_id = utxo_leases.wallet_id
    ) - (
        SELECT spend.block_height
        FROM utxos AS u
        INNER JOIN transactions AS spend ON u.spent_by_tx_id = spend.id
        WHERE u.id = utxo_leases.utxo_id
    ) + 1
    >= utxo_leases.release_after_spend_confs;
