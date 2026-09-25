-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if tables are already dropped or database in unexpected state.
DROP TRIGGER IF EXISTS trg_assert_wallet_is_watch_only_immutable;
DROP TRIGGER IF EXISTS trg_assert_watch_only_wallet_secrets_insert;
DROP TRIGGER IF EXISTS trg_assert_watch_only_wallet_secrets_update;
DROP TABLE IF EXISTS wallet_sync_states;
DROP TABLE IF EXISTS wallet_secrets;
DROP TABLE IF EXISTS wallets;
