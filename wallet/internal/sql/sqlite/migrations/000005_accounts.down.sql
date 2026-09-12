-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if tables are already dropped or database is in unexpected state.
DROP TRIGGER IF EXISTS trg_assert_watch_only_account_secrets_insert;
DROP TRIGGER IF EXISTS trg_assert_watch_only_account_secrets_update;
DROP TRIGGER IF EXISTS trg_assert_account_identity_immutable;
DROP TABLE IF EXISTS account_secrets;
DROP TABLE IF EXISTS accounts;
