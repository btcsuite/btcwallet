-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if objects are already dropped or database is in an
-- unexpected state.
DROP TRIGGER IF EXISTS trg_mark_utxo_lease_spend_disconnected ON transactions;
DROP FUNCTION IF EXISTS mark_utxo_lease_spend_disconnected();
DROP TRIGGER IF EXISTS trg_assert_utxo_lease_wallet_consistency_insert ON utxo_leases;
DROP TRIGGER IF EXISTS trg_assert_utxo_lease_wallet_consistency_update ON utxo_leases;
DROP FUNCTION IF EXISTS assert_utxo_lease_wallet_consistency();
DROP TABLE IF EXISTS utxo_leases;
