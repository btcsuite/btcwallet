-- name: InsertTransaction :one
-- Inserts a wallet-scoped transaction row and returns its database ID.
--
-- How:
-- - Writes only the transactions table.
-- - Expects the caller to have already resolved wallet scope and any optional
--   block reference.
-- - Expects the caller to supply the initial status explicitly so unmined rows
--   do not have to guess between `pending` and `published`.
-- Performance:
-- - Single-row insert. The cost is dominated by the wallet/hash uniqueness
--   checks and any optional block foreign-key validation.
INSERT INTO transactions (
    wallet_id,
    tx_hash,
    raw_tx,
    block_height,
    confirmed_order,
    tx_status,
    received_time,
    is_coinbase,
    tx_label
) VALUES (
    sqlc.arg('wallet_id'),
    sqlc.arg('tx_hash'),
    sqlc.arg('raw_tx'),
    cast(sqlc.narg('block_height') AS INTEGER),
    CASE
        WHEN cast(sqlc.narg('block_height') AS INTEGER) IS NULL THEN NULL
        ELSE (
            SELECT coalesce(max(confirmed_order), 0) + 1
            FROM transactions
        )
    END,
    sqlc.arg('tx_status'),
    sqlc.arg('received_time'),
    sqlc.arg('is_coinbase'),
    sqlc.arg('tx_label')
)
RETURNING id;

-- name: GetTransactionMetaByHash :one
-- Retrieves the primary key and lightweight transaction metadata.
--
-- How:
-- - Reads only the transactions table because callers only need row identity
--   plus lightweight status/label fields.
-- Performance:
-- - Uses the wallet-scoped unique `(wallet_id, tx_hash)` lookup path.
SELECT
    id,
    block_height,
    is_coinbase,
    tx_status,
    tx_label
FROM transactions
WHERE wallet_id = ? AND tx_hash = ?;

-- name: GetTransactionByHash :one
-- Retrieves the full transaction row along with optional block metadata.
--
-- How:
-- - Looks up the transaction by `(wallet_id, tx_hash)`.
-- - LEFT JOINs blocks on `block_height` so the same query handles mined and
--   unmined rows.
-- Performance:
-- - The unique transaction lookup limits the join fanout to at most one block
--   row.
SELECT
    t.id,
    t.tx_hash,
    t.raw_tx,
    t.received_time,
    t.block_height,
    b.header_hash AS block_hash,
    b.block_timestamp,
    t.is_coinbase,
    t.tx_status,
    t.tx_label
FROM transactions AS t
LEFT JOIN blocks AS b ON t.block_height = b.block_height
WHERE t.wallet_id = ? AND t.tx_hash = ?;

-- name: ListTransactionsWithoutBlock :many
-- Lists every wallet transaction row that currently has no confirming block.
--
-- How:
-- - Reads from transactions only and filters on rows with no confirming block.
-- - Includes the active unmined set (`pending` and `published`) together with
--   retained invalid history such as `failed`, `replaced`, or `orphaned`
--   rows.
-- - Projects typed NULL block metadata through `LEFT JOIN blocks AS b ON 1 = 0`
--   so sqlc preserves the nullable block columns while the row shape stays
--   aligned with the confirmed query below.
-- Performance:
-- - Matches the dedicated no-confirming-block history index.
SELECT
    t.id,
    t.tx_hash,
    t.raw_tx,
    t.received_time,
    t.block_height,
    b.header_hash AS block_hash,
    b.block_timestamp,
    t.is_coinbase,
    t.tx_status,
    t.tx_label
FROM transactions AS t
LEFT JOIN blocks AS b ON 1 = 0
WHERE
    t.wallet_id = ?
    AND t.block_height IS NULL
ORDER BY t.received_time DESC, t.id DESC;

-- name: ListUnminedTransactions :many
-- Lists the wallet transactions that still belong to the active unmined set.
--
-- How:
-- - Reads from transactions only and filters on unmined rows that are still
--   in unmined `pending` or `published` status.
-- - Excludes orphaned/replaced/failed history so delete and rollback logic do
--   not treat retained invalid rows as active mempool spends.
-- - Projects typed NULL block metadata through `LEFT JOIN blocks AS b ON 1 = 0`
--   so sqlc preserves the nullable block columns while the row shape stays
--   aligned with other transaction queries.
-- Performance:
-- - Matches the dedicated unmined-history index while the more selective
--   live-only partial index stays available for conflict paths.
SELECT
    t.id,
    t.tx_hash,
    t.raw_tx,
    t.received_time,
    t.block_height,
    b.header_hash AS block_hash,
    b.block_timestamp,
    t.is_coinbase,
    t.tx_status,
    t.tx_label
FROM transactions AS t
LEFT JOIN blocks AS b ON 1 = 0
WHERE
    t.wallet_id = ?
    AND t.block_height IS NULL
    AND t.tx_status IN (0, 1)
ORDER BY t.received_time DESC, t.id DESC;

-- name: ListTransactionsByHeightRange :many
-- Lists all confirmed transactions for a wallet in the provided height range.
--
-- How:
-- - Reads transactions in a wallet-scoped block-height range.
-- - INNER JOINs blocks on the natural `block_height` key to hydrate block hash
--   and timestamp for confirmed rows.
-- Performance:
-- - The `(wallet_id, block_height, confirmed_order)` index bounds the scan and
--   preserves wallet-observed order within each block before the single-row
--   block join.
SELECT
    t.id,
    t.tx_hash,
    t.raw_tx,
    t.received_time,
    t.block_height,
    b.header_hash AS block_hash,
    b.block_timestamp,
    t.is_coinbase,
    t.tx_status,
    t.tx_label
FROM transactions AS t
INNER JOIN blocks AS b ON t.block_height = b.block_height
WHERE
    t.wallet_id = sqlc.arg('wallet_id')
    AND t.block_height >= cast(sqlc.arg('start_height') AS INTEGER)
    AND t.block_height <= cast(sqlc.arg('end_height') AS INTEGER)
ORDER BY t.block_height, t.confirmed_order, t.id;

-- name: ListOwnedOutputsByTxIDs :many
-- ListOwnedOutputsByTxIDs lists wallet-owned outputs created by the selected
-- transaction rows.
--
-- How:
-- - Reads directly from utxos by `tx_id` after the caller has already selected
--   the wallet-scoped transaction rows.
-- - Returns only the output indexes and amounts needed by the tx detail read
--   model.
-- Performance:
-- - Uses the provided tx-id slice to bound the scan to the selected rows.
SELECT
    u.tx_id,
    u.output_index,
    u.amount
FROM utxos AS u
INNER JOIN transactions AS t ON u.tx_id = t.id
INNER JOIN addresses AS a ON u.address_id = a.id
INNER JOIN accounts AS acc ON a.account_id = acc.id
INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
WHERE
    t.wallet_id = sqlc.arg('wallet_id')
    AND ks.wallet_id = sqlc.arg('wallet_id')
    AND u.tx_id IN (sqlc.slice('tx_ids'))
ORDER BY u.tx_id, u.output_index;

-- name: ListOwnedInputPrevOutputsByTxHashes :many
-- ListOwnedInputPrevOutputsByTxHashes lists wallet-owned previous outputs that
-- may be spent by selected transaction inputs.
--
-- How:
-- - Resolves previous transaction hashes to this wallet's tracked UTXO rows.
-- - Rejoins addresses -> accounts -> key_scopes so debit reconstruction does
--   not depend only on transaction wallet scope.
-- - Does not read `spent_by_tx_id` because invalidation and rollback can clear
--   that mutable edge while the historical spending transaction still exists.
-- Performance:
-- - Uses one batched transaction-hash lookup, then the UTXO tx-id index for the
--   previous transactions' wallet-owned outputs.
SELECT
    t.tx_hash,
    u.output_index,
    u.amount
FROM transactions AS t
INNER JOIN utxos AS u ON t.id = u.tx_id
INNER JOIN addresses AS a ON u.address_id = a.id
INNER JOIN accounts AS acc ON a.account_id = acc.id
INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
WHERE
    t.wallet_id = sqlc.arg('wallet_id')
    AND ks.wallet_id = sqlc.arg('wallet_id')
    AND t.tx_hash IN (sqlc.slice('tx_hashes'))
ORDER BY t.tx_hash, u.output_index;

-- name: UpdateTransactionLabelByHash :execrows
-- Updates only the user-visible transaction label.
--
-- How:
-- - Leaves block assignment and status untouched.
-- - Exists for user-facing metadata edits only; wallet-internal state
--   transitions use dedicated helper queries.
-- Performance:
-- - Updates at most one row through the wallet-scoped unique tx-hash lookup.
UPDATE transactions
SET tx_label = sqlc.arg('label')
WHERE
    wallet_id = sqlc.arg('wallet_id')
    AND tx_hash = sqlc.arg('tx_hash');

-- name: UpdateTransactionStateByHash :execrows
-- Updates the stored block assignment and wallet-relative status for one
-- transaction row.
--
-- How:
-- - Leaves immutable transaction facts such as `raw_tx`, credits, and spent
--   inputs untouched.
-- - Leaves the user-visible label untouched so callers can patch label and
--   state independently or together inside one SQL transaction.
-- - Expects callers to validate any required block reference and state
--   invariants before issuing the update.
-- Performance:
-- - Updates at most one row through the wallet-scoped unique tx-hash lookup.
UPDATE transactions
SET
    confirmed_order = CASE
        WHEN cast(sqlc.narg('block_height') AS INTEGER) IS NULL THEN NULL
        WHEN
            transactions.block_height = cast(sqlc.narg('block_height') AS INTEGER)
            AND transactions.confirmed_order IS NOT NULL
            THEN transactions.confirmed_order
        ELSE (
            SELECT coalesce(max(confirmed_order), 0) + 1
            FROM transactions
        )
    END,
    block_height = cast(sqlc.narg('block_height') AS INTEGER),
    tx_status = sqlc.arg('status')
WHERE
    transactions.wallet_id = sqlc.arg('wallet_id')
    AND transactions.tx_hash = sqlc.arg('tx_hash');

-- name: UpdateTransactionStatusByIDs :execrows
-- Updates the wallet-relative status for a set of transaction row IDs.
--
-- How:
-- - Exists for wallet-internal replacement and invalidation flows after the
--   caller has already identified the affected rows.
-- - Leaves block assignment untouched; rollback/disconnect continues to use the
--   dedicated rewind helpers below.
-- Performance:
-- - Restricts by wallet scope first, then matches only the provided ID set.
UPDATE transactions
SET tx_status = sqlc.arg('status')
WHERE
    wallet_id = sqlc.arg('wallet_id')
    AND id IN (sqlc.slice('tx_ids'));

-- name: DeleteUnminedTransactionByHash :execrows
-- Deletes an unconfirmed transaction row.
--
-- How:
-- - Deletes only rows whose `block_height` is still NULL and whose status is
--   still unmined `pending` or `published`.
-- - Preserves orphaned/replaced/failed history; those rows must remain visible
--   for audit/reorg handling instead of being treated as ordinary mempool data.
-- - The caller must delete or restore dependent UTXO rows first.
-- Performance:
-- - Targets at most one row by `(wallet_id, tx_hash)`.
DELETE FROM transactions
WHERE
    wallet_id = ?
    AND tx_hash = ?
    AND block_height IS NULL
    AND tx_status IN (0, 1);

-- name: ListRollbackCoinbaseRoots :many
-- Lists wallet-scoped coinbase transaction hashes at or above the rollback
-- boundary that seed descendant invalidation.
--
-- How:
-- - Reads only confirmed coinbase rows at or above the rollback boundary.
-- - Returns wallet scope alongside each tx hash so callers can treat these
--   coinbase transactions as rollback roots when invalidating now-invalid
--   descendants inside the same rollback transaction.
-- - This is a rollback-specific helper, not a generic "coinbase txs from one
--   block" listing query.
-- Performance:
-- - Uses the block-height index to bound the scan to the rollback range.
SELECT
    wallet_id,
    tx_hash
FROM transactions
WHERE
    block_height >= cast(sqlc.arg('rollback_height') AS INTEGER)
    AND is_coinbase
ORDER BY wallet_id, id;

-- name: RewindWalletSyncStateHeightsForRollback :execrows
-- Rewrites wallet sync-state heights so they stop referencing blocks that are
-- about to be deleted during RollbackToBlock.
--
-- How:
-- - Computes the greatest stored block below the rollback boundary.
-- - Rewrites both synced_height and birthday_height in one statement so the
--   subsequent block delete does not violate `ON DELETE RESTRICT`.
-- - Example: if `rollback_height = 195`, affected sync heights rewind to the
--   greatest stored block below 195, not necessarily 194 on sparse block tables.
-- - If there is no stored block below the boundary, the sync state no longer
--   points at any surviving block row.
-- Performance:
-- - Touches only wallet_sync_states rows whose heights are at or above the
--   rollback boundary.
UPDATE wallet_sync_states
SET
    synced_height = CASE
        WHEN
            synced_height IS NOT NULL
            AND synced_height >= cast(sqlc.arg('rollback_height') AS INTEGER)
            THEN (
                SELECT max(block_height)
                FROM blocks
                WHERE block_height < cast(sqlc.arg('rollback_height') AS INTEGER)
            )
        ELSE synced_height
    END,
    birthday_height = CASE
        WHEN
            birthday_height IS NOT NULL
            AND birthday_height >= cast(sqlc.arg('rollback_height') AS INTEGER)
            THEN (
                SELECT max(block_height)
                FROM blocks
                WHERE block_height < cast(sqlc.arg('rollback_height') AS INTEGER)
            )
        ELSE birthday_height
    END,
    updated_at = current_timestamp
WHERE
    (
        synced_height IS NOT NULL
        AND synced_height >= cast(sqlc.arg('rollback_height') AS INTEGER)
    )
    OR (
        birthday_height IS NOT NULL
        AND birthday_height >= cast(sqlc.arg('rollback_height') AS INTEGER)
    );

-- name: DeleteBlocksAtOrAboveHeight :execrows
-- Deletes blocks at and after the provided height.
--
-- How:
-- - Deletes directly from blocks by the natural height key.
-- - Relies on FK/trigger side effects to null transaction block references and
--   orphan coinbase rows.
-- Performance:
-- - Executes as a range delete over the block-height primary key.
DELETE FROM blocks
WHERE block_height >= ?;
