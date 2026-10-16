-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if objects are already dropped or database is in an
-- unexpected state.
DROP TRIGGER IF EXISTS trg_track_utxo_lease_spend_on_utxo_spend ON utxos;
DROP FUNCTION IF EXISTS track_utxo_lease_spend_on_utxo_spend();
DROP TRIGGER IF EXISTS trg_track_utxo_lease_spend_on_tx_block ON transactions;
DROP FUNCTION IF EXISTS track_utxo_lease_spend_on_tx_block();
DROP INDEX IF EXISTS idx_utxo_leases_spend_maturity;
ALTER TABLE utxo_leases DROP CONSTRAINT IF EXISTS check_utxo_lease_spend_progress;
ALTER TABLE utxo_leases DROP COLUMN IF EXISTS confirmed_spend_height;
ALTER TABLE utxo_leases DROP COLUMN IF EXISTS release_after_spend_confs;
