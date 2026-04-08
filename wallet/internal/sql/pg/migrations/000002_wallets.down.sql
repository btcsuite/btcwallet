-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if tables are already dropped or database in unexpected state.
DROP TABLE IF EXISTS wallet_sync_states;
DROP TABLE IF EXISTS wallet_secrets;
DROP TABLE IF EXISTS wallets;
