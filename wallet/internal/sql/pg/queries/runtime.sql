-- name: EnsureRuntimeState :exec
-- EnsureRuntimeState creates the zeroed runtime-state row for a wallet when it
-- does not exist yet so the guard queries always operate on an existing row. It
-- is idempotent: an existing row is left untouched.
INSERT INTO wallet_runtime_states (wallet_id)
VALUES ($1)
ON CONFLICT (wallet_id) DO NOTHING;

-- name: GetRuntimeState :one
SELECT state_version, history_epoch, secret_version
FROM wallet_runtime_states
WHERE wallet_id = $1;

-- name: BumpStateVersion :execrows
-- BumpStateVersion increments the address/transaction/sync state version only
-- while it still equals the expected value, implementing the optimistic
-- compare-and-swap guard. Zero affected rows means the caller's snapshot was
-- stale and no version was advanced.
UPDATE wallet_runtime_states
SET state_version = state_version + 1
WHERE wallet_id = sqlc.arg('wallet_id')
    AND state_version = sqlc.arg('expected_version');

-- name: BumpHistoryEpoch :execrows
-- BumpHistoryEpoch advances the history epoch only while it still equals the
-- expected value. Zero affected rows means the snapshot was stale.
UPDATE wallet_runtime_states
SET history_epoch = history_epoch + 1
WHERE wallet_id = sqlc.arg('wallet_id')
    AND history_epoch = sqlc.arg('expected_version');

-- name: BumpSecretVersion :execrows
-- BumpSecretVersion advances the secret version only while it still equals the
-- expected value. Zero affected rows means the snapshot was stale.
UPDATE wallet_runtime_states
SET secret_version = secret_version + 1
WHERE wallet_id = sqlc.arg('wallet_id')
    AND secret_version = sqlc.arg('expected_version');

-- name: GetOperation :one
SELECT
    request_hash,
    history_epoch,
    status,
    result_ref,
    result_hash,
    created_at,
    expires_at
FROM operation_journal
WHERE wallet_id = $1 AND domain = $2 AND operation_id = $3;

-- name: InsertCommittedOperation :exec
-- InsertCommittedOperation records a semantic operation that has already
-- committed. Callers write this row and its result facts in the same
-- transaction as the domain mutation, so the started state is never durably
-- visible and a later retry is served from the journal.
INSERT INTO operation_journal (
    wallet_id,
    domain,
    operation_id,
    request_hash,
    history_epoch,
    status,
    result_ref,
    result_hash,
    created_at,
    expires_at
) VALUES ($1, $2, $3, $4, $5, 'committed', $6, $7, $8, $9);

-- name: InsertOperationResultFact :exec
INSERT INTO operation_result_facts (
    wallet_id,
    domain,
    operation_id,
    ordinal,
    fact_type,
    fact_key,
    fact_payload
) VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ListOperationResultFacts :many
SELECT ordinal, fact_type, fact_key, fact_payload
FROM operation_result_facts
WHERE wallet_id = $1 AND domain = $2 AND operation_id = $3
ORDER BY ordinal;

-- name: CollectExpiredOperations :execrows
-- CollectExpiredOperations deletes terminal journal rows whose retention
-- deadline has passed, cascading their result facts. The expires_at predicate
-- guarantees an unexpired row is never collected, and the status filter leaves
-- an in-flight started row untouched.
DELETE FROM operation_journal
WHERE wallet_id = sqlc.arg('wallet_id')
    AND expires_at <= sqlc.arg('now_unix')
    AND status IN ('committed', 'aborted', 'expired', 'rejected');
