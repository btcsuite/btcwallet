-- name: InsertTxReplacementEdge :execrows
-- Records a replacement edge between two wallet-scoped transactions.
--
-- How:
-- - Writes directly to tx_replacements using already-resolved transaction IDs.
-- - Uses an explicit conflict target so only duplicate edges are ignored;
--   missing transaction IDs, self-replacements, and other constraint failures
--   still surface to the caller.
-- Performance:
-- - Single-row insert with cheap duplicate suppression via `ON CONFLICT`.
INSERT INTO tx_replacements (
    wallet_id,
    replaced_tx_id,
    replacement_tx_id
) VALUES (
    ?1, ?2, ?3
)
ON CONFLICT (wallet_id, replaced_tx_id, replacement_tx_id) DO NOTHING;

-- name: InsertTxReplacementEdgeByHash :execrows
-- Records a replacement edge by resolving tx IDs from transaction hashes.
--
-- How:
-- - Resolves both endpoint transaction IDs from the transactions table using
--   the wallet-scoped tx-hash unique lookup.
-- - Writes the resulting directed edge to tx_replacements.
-- - Uses an explicit conflict target so duplicate-edge retries are ignored
--   without masking missing-hash or check-constraint failures.
-- Performance:
-- - Trades two indexed scalar subqueries for one network round trip, which is
--   preferable when callers start from tx hashes.
INSERT INTO tx_replacements (
    wallet_id,
    replaced_tx_id,
    replacement_tx_id
) VALUES (
    ?1,
    (
        SELECT t.id
        FROM transactions AS t
        WHERE t.wallet_id = ?1 AND t.tx_hash = ?2
    ),
    (
        SELECT t.id
        FROM transactions AS t
        WHERE t.wallet_id = ?1 AND t.tx_hash = ?3
    )
)
ON CONFLICT (wallet_id, replaced_tx_id, replacement_tx_id) DO NOTHING;

-- name: ListReplacementTxIDsByReplacedTxID :many
-- Lists replacement transaction IDs for a given victim transaction ID.
--
-- How:
-- - Reads tx_replacements directly by `(wallet_id, replaced_tx_id)` because the
--   caller already has the victim's internal row ID.
-- - Orders first by created_at and then by id so traversal stays deterministic
--   even when several edges share the same timestamp.
-- Performance:
-- - Uses the replacement-edge index without joining transactions.
SELECT
    replacement_tx_id,
    created_at
FROM tx_replacements
WHERE wallet_id = ?1 AND replaced_tx_id = ?2
ORDER BY created_at, id;

-- name: ListReplacedTxIDsByReplacementTxID :many
-- Lists victim transaction IDs for a given replacement transaction ID.
--
-- How:
-- - Reads tx_replacements directly by `(wallet_id, replacement_tx_id)` because
--   the caller already has the replacement row ID.
-- - Orders first by created_at and then by id so traversal stays deterministic
--   even when several edges share the same timestamp.
-- Performance:
-- - Uses the inverse replacement lookup index without joining transactions.
SELECT
    replaced_tx_id,
    created_at
FROM tx_replacements
WHERE wallet_id = ?1 AND replacement_tx_id = ?2
ORDER BY created_at, id;

-- name: ListReplacementTxHashesByReplacedTxHash :many
-- Lists replacement txids for a given victim txid.
--
-- How:
-- - Starts from tx_replacements, then joins transactions twice on `(wallet_id,
--   id)` to map both edge endpoints back to network tx hashes.
-- - Filters by the victim hash on the `replaced` alias.
-- Performance:
-- - The victim hash lookup narrows the graph walk before the second transaction
--   join materializes replacement hashes.
SELECT
    replacement.tx_hash AS replacement_tx_hash,
    r.created_at
FROM tx_replacements AS r
INNER JOIN transactions AS replaced
    ON r.wallet_id = replaced.wallet_id AND r.replaced_tx_id = replaced.id
INNER JOIN transactions AS replacement
    ON
        r.wallet_id = replacement.wallet_id
        AND r.replacement_tx_id = replacement.id
WHERE r.wallet_id = ?1 AND replaced.tx_hash = ?2
ORDER BY r.created_at, r.id;

-- name: ListReplacedTxHashesByReplacementTxHash :many
-- Lists victim txids for a given replacement txid.
--
-- How:
-- - Starts from tx_replacements, then joins transactions twice on `(wallet_id,
--   id)` to map both edge endpoints back to network tx hashes.
-- - Filters by the replacement hash on the `replacement` alias.
-- Performance:
-- - Mirrors the victim lookup path while keeping the graph traversal bounded by
--   wallet scope and indexed edge keys.
SELECT
    replaced.tx_hash AS replaced_tx_hash,
    r.created_at
FROM tx_replacements AS r
INNER JOIN transactions AS replaced
    ON r.wallet_id = replaced.wallet_id AND r.replaced_tx_id = replaced.id
INNER JOIN transactions AS replacement
    ON
        r.wallet_id = replacement.wallet_id
        AND r.replacement_tx_id = replacement.id
WHERE r.wallet_id = ?1 AND replacement.tx_hash = ?2
ORDER BY r.created_at, r.id;
