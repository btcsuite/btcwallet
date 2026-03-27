-- name: InsertUtxo :one
-- Inserts a new UTXO row and returns its database ID.
--
-- How:
-- - Writes only the utxos table using already-resolved transaction and address
--   IDs.
-- - Rejoins addresses -> accounts -> key_scopes so the insert only succeeds if
--   the provided address ID belongs to the same wallet.
-- Performance:
-- - Single-row insert. The main cost is the wallet-ownership validation join
--   plus FK and uniqueness checks.
INSERT INTO utxos (
    tx_id,
    output_index,
    amount,
    address_id
) SELECT
    t.id AS tx_id,
    sqlc.arg('output_index') AS output_index,
    sqlc.arg('amount') AS amount,
    a.id AS address_id
FROM addresses AS a
INNER JOIN accounts AS acc ON a.account_id = acc.id
INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
CROSS JOIN transactions AS t
WHERE
    t.id = sqlc.arg('tx_id')
    AND t.wallet_id = sqlc.arg('wallet_id')
    AND t.tx_status IN (0, 1)
    AND
    a.id = sqlc.arg('address_id')
    AND ks.wallet_id = sqlc.arg('wallet_id')
RETURNING id;

-- name: GetUtxoIDByOutpoint :one
-- Retrieves the database ID for a current UTXO by its outpoint.
--
-- How:
-- - Joins transactions on `id` so callers can address a UTXO by
--   network outpoint (`tx_hash`, `output_index`) instead of the internal row ID.
-- - Restricts the result to unspent outputs whose parent transaction is still
--   `pending` or `published`.
-- - Rejoins addresses -> accounts -> key_scopes so helper lookups do not return
--   rows whose credited address does not actually belong to the wallet.
-- - Exists separately from GetUtxoByOutpoint because mutation helpers often
--   need the stable internal UTXO row ID without reading the full public UTXO
--   payload.
-- Performance:
-- - Uses the wallet-scoped transaction hash lookup first, then narrows to the
--   unique `(tx_id, output_index)` outpoint.
SELECT u.id
FROM transactions AS t
INNER JOIN utxos AS u ON t.id = u.tx_id
INNER JOIN addresses AS a ON u.address_id = a.id
INNER JOIN accounts AS acc ON a.account_id = acc.id
INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
WHERE
    t.wallet_id = ?1
    AND ks.wallet_id = ?1
    AND t.tx_hash = ?2
    AND u.output_index = ?3
    AND u.spent_by_tx_id IS NULL
    AND t.tx_status IN (0, 1);

-- name: GetUtxoByOutpoint :one
-- Retrieves a single unspent UTXO by its outpoint.
--
-- How:
-- - Joins utxos -> transactions on `tx_id` to resolve the outpoint
--   from tx hash plus output index.
-- - Joins addresses -> accounts -> key_scopes so the read path reasserts that
--   the credited address belongs to the requested wallet.
-- - Returns leased and unleased outputs alike because leasing affects coin
--   selection, not whether the UTXO exists.
-- - Treats outputs from unmined `pending` and `published` parent transactions
--   as part of the wallet's current UTXO set.
-- Performance:
-- - The wallet-scoped tx hash lookup and unique outpoint constraint keep the
--   join fanout to at most one candidate output.
SELECT
    t.tx_hash,
    u.output_index,
    u.amount,
    a.script_pub_key,
    t.received_time,
    t.is_coinbase,
    t.block_height
FROM transactions AS t
INNER JOIN utxos AS u ON t.id = u.tx_id
INNER JOIN addresses AS a ON u.address_id = a.id
INNER JOIN accounts AS acc ON a.account_id = acc.id
INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
WHERE
    t.wallet_id = ?1
    AND ks.wallet_id = ?1
    AND t.tx_hash = ?2
    AND u.output_index = ?3
    AND u.spent_by_tx_id IS NULL
    AND t.tx_status IN (0, 1);

-- name: ListUtxos :many
-- Lists unspent UTXOs that match the provided filters.
--
-- How:
-- - Starts from utxos and joins transactions for tx metadata plus
--   wallet_sync_states for confirmation math.
-- - Joins addresses to return the required script_pub_key, then reuses
--   addresses -> accounts -> key_scopes so account filtering and wallet
--   ownership checks happen in the same read.
-- - Returns leased outputs too because the API models leases separately from
--   UTXO existence.
-- - Includes outputs whose parent transaction is still in `pending` or
--   `published` status.
-- - Intentionally does not enforce coinbase maturity because this query models
--   wallet-owned UTXO existence rather than a strictly spendable subset.
-- Performance:
-- - Restricts first by wallet, spend state, and transaction status.
-- - Uses the address/account/scope joins to keep ownership validation and
--   account filtering in one pass.
-- - Treats min/max confirmations as optional filters so callers can
--   distinguish "not set" from an explicit zero-conf request.
SELECT
    t.tx_hash,
    u.output_index,
    u.amount,
    a.script_pub_key,
    t.received_time,
    t.is_coinbase,
    t.block_height
FROM transactions AS t
INNER JOIN utxos AS u ON t.id = u.tx_id
INNER JOIN addresses AS a ON u.address_id = a.id
INNER JOIN accounts AS acc ON a.account_id = acc.id
INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
LEFT JOIN wallet_sync_states AS s ON t.wallet_id = s.wallet_id
WHERE
    t.wallet_id = sqlc.arg('wallet_id')
    AND ks.wallet_id = sqlc.arg('wallet_id')
    AND u.spent_by_tx_id IS NULL
    AND t.tx_status IN (0, 1)
    AND (
        sqlc.narg('account_number') IS NULL
        OR acc.account_number = sqlc.narg('account_number')
    )
    AND (
        sqlc.narg('min_confirms') IS NULL
        OR sqlc.narg('min_confirms') = 0
        OR (
            CASE
                WHEN t.block_height IS NULL THEN 0
                WHEN s.synced_height IS NULL THEN NULL
                WHEN t.block_height > s.synced_height THEN NULL
                ELSE s.synced_height - t.block_height + 1
            END
        ) >= sqlc.narg('min_confirms')
    )
    AND (
        sqlc.narg('max_confirms') IS NULL
        OR (
            CASE
                WHEN t.block_height IS NULL THEN 0
                WHEN s.synced_height IS NULL THEN NULL
                WHEN t.block_height > s.synced_height THEN NULL
                ELSE s.synced_height - t.block_height + 1
            END
        ) <= sqlc.narg('max_confirms')
    )
ORDER BY u.amount, t.tx_hash, u.output_index;

-- name: Balance :one
-- Returns the total and locked value represented by the wallet's current
-- unspent UTXO set.
--
-- How:
-- - Starts from wallet-scoped unspent outputs and rejoins transactions plus
--   wallet_sync_states for confirmation math.
-- - Rejoins addresses -> accounts -> key_scopes so ownership validation and
--   optional account filtering stay in one read.
-- - Applies optional confirmation-range and coinbase-maturity policy directly
--   inside the aggregate query so callers can request factual or policy-shaped
--   balance reads through one public method.
-- - Returns both the total matching value and the locked subset covered by
--   active leases after the same filters are applied.
-- Performance:
-- - Executes as one aggregate over wallet-scoped outputs whose parent
--   transaction is still `pending` or `published`.
-- - Uses a filtered aggregate over active leases rather than issuing a second
--   query for the locked subset.
-- - Uses the address/account/scope joins to keep ownership validation and
--   account filtering in one pass.
SELECT
    cast(coalesce(sum(u.amount), 0) AS INTEGER) AS total_balance,
    cast(
        coalesce(
            sum(
                CASE
                    WHEN EXISTS (
                        SELECT 1
                        FROM utxo_leases AS l
                        WHERE
                            l.wallet_id = t.wallet_id
                            AND l.utxo_id = u.id
                            AND l.expires_at > sqlc.arg('now_utc')
                    ) THEN u.amount
                    ELSE 0
                END
            ),
            0
        ) AS INTEGER
    ) AS locked_balance
FROM transactions AS t
INNER JOIN utxos AS u ON t.id = u.tx_id
INNER JOIN addresses AS a ON u.address_id = a.id
INNER JOIN accounts AS acc ON a.account_id = acc.id
INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
LEFT JOIN wallet_sync_states AS s ON t.wallet_id = s.wallet_id
WHERE
    t.wallet_id = sqlc.arg('wallet_id')
    AND ks.wallet_id = sqlc.arg('wallet_id')
    AND u.spent_by_tx_id IS NULL
    AND t.tx_status IN (0, 1)
    AND (
        sqlc.narg('account_number') IS NULL
        OR acc.account_number = sqlc.narg('account_number')
    )
    AND (
        sqlc.narg('min_confirms') IS NULL
        OR sqlc.narg('min_confirms') = 0
        OR (
            CASE
                WHEN t.block_height IS NULL THEN 0
                WHEN s.synced_height IS NULL THEN NULL
                WHEN t.block_height > s.synced_height THEN NULL
                ELSE s.synced_height - t.block_height + 1
            END
        ) >= sqlc.narg('min_confirms')
    )
    AND (
        sqlc.narg('max_confirms') IS NULL
        OR (
            CASE
                WHEN t.block_height IS NULL THEN 0
                WHEN s.synced_height IS NULL THEN NULL
                WHEN t.block_height > s.synced_height THEN NULL
                ELSE s.synced_height - t.block_height + 1
            END
        ) <= sqlc.narg('max_confirms')
    )
    AND (
        sqlc.narg('coinbase_maturity') IS NULL
        OR sqlc.narg('coinbase_maturity') = 0
        OR NOT t.is_coinbase
        OR (
            CASE
                WHEN t.block_height IS NULL THEN 0
                WHEN s.synced_height IS NULL THEN NULL
                WHEN t.block_height > s.synced_height THEN NULL
                ELSE s.synced_height - t.block_height + 1
            END
        ) >= sqlc.narg('coinbase_maturity')
    );

-- name: ListSpendingTxIDsByParentTxID :many
-- Lists direct child transaction IDs for one parent transaction ID.
--
-- How:
-- - Reads the spend edges already materialized on utxos through
--   `(tx_id, spent_by_tx_id)`.
-- - Returns only direct children; callers that need full descendant walks should
--   traverse this query iteratively in application code.
-- Performance:
-- - Uses the `(tx_id)` and `(spent_by_tx_id)` indexes to keep the walk bounded
--   to one wallet-scoped parent.
SELECT DISTINCT u.spent_by_tx_id
FROM utxos AS u
WHERE
    u.tx_id = ?2
    AND u.spent_by_tx_id IS NOT NULL
    AND EXISTS (
        SELECT 1
        FROM transactions AS t
        WHERE t.id = u.tx_id AND t.wallet_id = ?1
    )
ORDER BY u.spent_by_tx_id;

-- name: GetUtxoSpendByOutpoint :one
-- Returns the current spend edge for one wallet-owned outpoint.
--
-- How:
-- - Resolves the parent transaction row from `(wallet_id, tx_hash)` and only
--   considers outputs whose parent status is `pending` or `published`.
-- - Returns the nullable `spent_by_tx_id` column so callers can distinguish
--   between an external/unknown parent and a wallet-owned conflict.
-- Performance:
-- - Targets one wallet-scoped outpoint through the unique `(tx_id,
--   output_index)` key after the parent hash lookup.
SELECT utxos.spent_by_tx_id
FROM transactions AS t
INNER JOIN utxos ON t.id = utxos.tx_id
WHERE
    t.wallet_id = ?1
    AND t.tx_hash = ?2
    AND utxos.output_index = ?3
    AND t.tx_status IN (0, 1);

-- name: MarkUtxoSpent :execrows
-- Marks a wallet-owned UTXO as spent by a transaction.
--
-- How:
-- - Resolves the created-by transaction row from `(wallet_id, tx_hash)` inside
--   the statement so callers can update by network outpoint.
-- - Requires the parent transaction status to be `pending` or `published`
--   before a child spend edge can attach.
-- - Only changes rows that are currently unspent or already point at the same
--   `(spent_by_tx_id, spent_input_index)` pair, which keeps retries idempotent
--   without allowing a caller to silently rewrite which input spent the UTXO.
-- Performance:
-- - Targets one outpoint in one wallet; the subquery uses the unique
--   wallet-scoped tx hash lookup.
UPDATE utxos
SET
    spent_by_tx_id = ?4,
    spent_input_index = ?5
WHERE
    utxos.tx_id = (
        SELECT t.id
        FROM transactions AS t
        WHERE
            t.wallet_id = ?1
            AND t.tx_hash = ?2
            AND t.tx_status IN (0, 1)
    )
    AND utxos.output_index = ?3
    AND (
        (utxos.spent_by_tx_id IS NULL AND utxos.spent_input_index IS NULL)
        OR (utxos.spent_by_tx_id = ?4 AND utxos.spent_input_index = ?5)
    );

-- name: ClearUtxosSpentByTxID :execrows
-- Clears spent_by pointers for all UTXOs spent by the provided transaction ID.
--
-- How:
-- - Resets both spent columns together so the logical spend pointer remains
--   internally consistent.
-- Performance:
-- - Uses the `(spent_by_tx_id)` index to find affected rows and rechecks wallet
--   ownership through the creating transaction.
UPDATE utxos
SET
    spent_by_tx_id = NULL,
    spent_input_index = NULL
WHERE
    spent_by_tx_id = ?2
    AND EXISTS (
        SELECT 1
        FROM transactions AS t
        WHERE t.id = utxos.tx_id AND t.wallet_id = ?1
    );

-- name: DeleteUtxosByTxID :execrows
-- Deletes all UTXO rows created by the provided transaction ID.
--
-- How:
-- - Removes outputs by the parent transaction's internal ID after callers have
--   already decided the transaction row itself may be deleted.
-- Performance:
-- - Uses the `(tx_id)` index to keep the delete bounded to one transaction's
--   outputs, then rechecks wallet ownership through the parent transaction.
DELETE FROM utxos
WHERE
    tx_id = ?2
    AND EXISTS (
        SELECT 1
        FROM transactions AS t
        WHERE t.id = utxos.tx_id AND t.wallet_id = ?1
    );
