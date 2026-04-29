-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if tables are already dropped or database is in unexpected state.
DROP TRIGGER IF EXISTS trg_assert_watch_only_account_secrets_insert ON account_secrets;
DROP TRIGGER IF EXISTS trg_assert_watch_only_account_secrets_update ON account_secrets;
DROP FUNCTION IF EXISTS assert_watch_only_account_secrets();
DROP TABLE IF EXISTS account_secrets;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS account_origins;
