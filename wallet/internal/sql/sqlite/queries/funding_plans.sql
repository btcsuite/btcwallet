-- name: InsertFundingPlan :one
-- InsertFundingPlan reserves a new funding plan and returns its surrogate id. A
-- plan starts in the reserved state and names no committed transaction.
INSERT INTO funding_plans (
    wallet_id, reservation_id, purpose, status, created_at, expires_at
) VALUES (?, ?, ?, 'reserved', ?, ?)
RETURNING id;

-- name: GetFundingPlan :one
SELECT id, reservation_id, purpose, status, created_at, expires_at,
       committed_tx_id
FROM funding_plans
WHERE wallet_id = ? AND reservation_id = ?;

-- name: ConsumeFundingPlan :execrows
-- ConsumeFundingPlan transitions a reserved plan to consumed and records the
-- transaction it funded. Zero affected rows means the plan was missing or no
-- longer reserved, which the caller reports as a reservation conflict.
UPDATE funding_plans
SET status = 'consumed', committed_tx_id = sqlc.narg('committed_tx_id')
WHERE wallet_id = sqlc.arg('wallet_id')
    AND reservation_id = sqlc.arg('reservation_id')
    AND status = 'reserved';

-- name: ReleaseFundingPlan :execrows
-- ReleaseFundingPlan transitions a reserved plan to released. Zero affected
-- rows means the plan was missing or no longer reserved.
UPDATE funding_plans
SET status = 'released'
WHERE wallet_id = ? AND reservation_id = ? AND status = 'reserved';

-- name: ExpireFundingPlan :execrows
-- ExpireFundingPlan transitions a reserved plan to expired. Zero affected rows
-- means the plan was missing or no longer reserved.
UPDATE funding_plans
SET status = 'expired'
WHERE wallet_id = ? AND reservation_id = ? AND status = 'reserved';

-- name: AcquireFundingPlanLease :execrows
-- AcquireFundingPlanLease adds one plan-owned lease under a reserved plan,
-- reusing the plan's reservation id as the durable lease lock id so the plan
-- and its leases share one owner token. Zero affected rows means the plan was
-- missing or no longer reserved.
INSERT INTO utxo_leases (
    wallet_id, tx_hash, output_index, lock_id, expires_unix,
    owner_type, funding_plan_id
)
SELECT
    fp.wallet_id, sqlc.arg('tx_hash'), sqlc.arg('output_index'),
    fp.reservation_id, sqlc.arg('expires_unix'), 'funding_plan', fp.id
FROM funding_plans AS fp
WHERE fp.wallet_id = sqlc.arg('wallet_id')
    AND fp.reservation_id = sqlc.arg('reservation_id')
    AND fp.status = 'reserved';

-- name: DeleteFundingPlanLeases :execrows
-- DeleteFundingPlanLeases removes only the leases owned by one plan and leaves
-- external leases untouched.
DELETE FROM utxo_leases
WHERE utxo_leases.wallet_id = sqlc.arg('wallet_id')
    AND utxo_leases.owner_type = 'funding_plan'
    AND utxo_leases.funding_plan_id = (
        SELECT funding_plans.id FROM funding_plans
        WHERE funding_plans.wallet_id = sqlc.arg('wallet_id')
            AND funding_plans.reservation_id = sqlc.arg('reservation_id')
    );

-- name: CollectExpiredFundingPlans :execrows
-- CollectExpiredFundingPlans deletes terminal plans past their retention
-- deadline, but never a plan that still owns leases, so a plan's durable lease
-- rows are always removed before the plan row.
DELETE FROM funding_plans
WHERE funding_plans.wallet_id = sqlc.arg('wallet_id')
    AND funding_plans.expires_at <= sqlc.arg('now_unix')
    AND funding_plans.status IN ('consumed', 'released', 'expired')
    AND NOT EXISTS (
        SELECT 1 FROM utxo_leases
        WHERE utxo_leases.wallet_id = funding_plans.wallet_id
            AND utxo_leases.owner_type = 'funding_plan'
            AND utxo_leases.funding_plan_id = funding_plans.id
    );
