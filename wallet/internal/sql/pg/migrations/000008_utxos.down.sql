-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if objects are already dropped or database is in an
-- unexpected state.
DROP TRIGGER IF EXISTS trg_assert_utxo_wallet_consistency_insert ON utxos;
DROP TRIGGER IF EXISTS trg_assert_utxo_wallet_consistency_update ON utxos;
DROP FUNCTION IF EXISTS assert_utxo_wallet_consistency();
DROP TABLE IF EXISTS utxos;
