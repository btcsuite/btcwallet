-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if tables are already dropped or database in unexpected state.
DROP TRIGGER IF EXISTS trg_assert_watch_only_wallet_secrets_insert ON wallet_secrets;
DROP TRIGGER IF EXISTS trg_assert_watch_only_wallet_secrets_update ON wallet_secrets;
DROP FUNCTION IF EXISTS assert_watch_only_wallet_secrets();
DROP TABLE IF EXISTS wallet_sync_states;
DROP TABLE IF EXISTS wallet_secrets;
DROP TABLE IF EXISTS wallets;
