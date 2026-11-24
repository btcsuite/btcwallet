DROP TABLE IF EXISTS wallet_blocks;
-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if table already dropped or database in unexpected state.
DROP TRIGGER IF EXISTS trg_assert_wallet_is_watch_only_immutable ON wallets;
DROP FUNCTION IF EXISTS assert_wallet_is_watch_only_immutable();
DROP TABLE IF EXISTS wallets;
