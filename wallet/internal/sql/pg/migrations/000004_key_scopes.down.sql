-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if tables are already dropped or database in unexpected state.
DROP TRIGGER IF EXISTS trg_assert_watch_only_key_scope_secrets_insert ON key_scope_secrets;
DROP TRIGGER IF EXISTS trg_assert_watch_only_key_scope_secrets_update ON key_scope_secrets;
DROP TRIGGER IF EXISTS trg_assert_key_scope_wallet_id_immutable ON key_scopes;
DROP FUNCTION IF EXISTS assert_watch_only_key_scope_secrets();
DROP FUNCTION IF EXISTS assert_key_scope_wallet_id_immutable();
DROP TABLE IF EXISTS key_scope_secrets;
DROP TABLE IF EXISTS key_scopes;
