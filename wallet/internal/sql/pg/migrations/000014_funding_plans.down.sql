-- Reverse the funding-plan and address/runtime guards. Every durable lease
-- outpoint row is preserved because leases are the exclusion primitive; a
-- plan-owned lease is demoted to a plain external lease as the funding_plans
-- grouping is dropped. No lease exclusion is discarded.

-- Drop the derived-address derivation-path uniqueness.
DROP INDEX IF EXISTS uidx_addresses_derivation_path;

-- Drop the plan owner columns and their constraints so utxo_leases no longer
-- references funding_plans.
DROP INDEX IF EXISTS idx_utxo_leases_funding_plan;
ALTER TABLE utxo_leases
    DROP CONSTRAINT IF EXISTS utxo_leases_owner_plan_check,
    DROP CONSTRAINT IF EXISTS utxo_leases_funding_plan_fkey,
    DROP COLUMN IF EXISTS funding_plan_id,
    DROP COLUMN IF EXISTS owner_type;

-- utxo_leases no longer references funding_plans, so the grouping table can be
-- dropped without a foreign-key restriction.
DROP TABLE IF EXISTS funding_plans;
