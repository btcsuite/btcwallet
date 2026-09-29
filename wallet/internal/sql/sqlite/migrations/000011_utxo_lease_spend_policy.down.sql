-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if objects are already dropped or database is in an
-- unexpected state.
DROP TRIGGER IF EXISTS trg_track_utxo_lease_spend_on_utxo_spend;
DROP TRIGGER IF EXISTS trg_track_utxo_lease_spend_on_tx_block;
DROP INDEX IF EXISTS idx_utxo_leases_spend_maturity;

-- SQLite has no IF EXISTS form for column drops. The progress check names the
-- depth column, so drop progress first.
ALTER TABLE utxo_leases DROP COLUMN confirmed_spend_height;
ALTER TABLE utxo_leases DROP COLUMN release_after_spend_confs;
