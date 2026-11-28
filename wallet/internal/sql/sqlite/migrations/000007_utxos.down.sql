-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if objects are already dropped or database is in an
-- unexpected state.
DROP VIEW IF EXISTS outputs_to_watch;
DROP TABLE IF EXISTS utxos;
