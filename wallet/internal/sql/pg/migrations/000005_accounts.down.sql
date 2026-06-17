-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if tables are already dropped or database is in unexpected state.
DROP TRIGGER IF EXISTS trg_assert_watch_only_account_secrets_insert ON account_secrets;
DROP TRIGGER IF EXISTS trg_assert_watch_only_account_secrets_update ON account_secrets;
DROP TRIGGER IF EXISTS trg_assert_derived_account_parent_insert ON derived_accounts;
DROP TRIGGER IF EXISTS trg_reject_derived_account_update ON derived_accounts;
DROP TRIGGER IF EXISTS trg_assert_account_identity_immutable ON accounts;
DROP FUNCTION IF EXISTS assert_watch_only_account_secrets();
DROP FUNCTION IF EXISTS reject_derived_account_update();
DROP FUNCTION IF EXISTS assert_derived_account_parent();
DROP FUNCTION IF EXISTS assert_account_identity_immutable();
DROP TABLE IF EXISTS account_secrets;
DROP TABLE IF EXISTS derived_accounts;
DROP TABLE IF EXISTS accounts;
