-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if tables are already dropped or database in unexpected state.
DROP TRIGGER IF EXISTS trg_assert_watch_only_key_scope_secrets_insert;
DROP TRIGGER IF EXISTS trg_assert_watch_only_key_scope_secrets_update;
DROP TRIGGER IF EXISTS trg_assert_key_scope_wallet_id_immutable;
DROP TABLE IF EXISTS key_scope_secrets;
DROP TABLE IF EXISTS key_scopes;
