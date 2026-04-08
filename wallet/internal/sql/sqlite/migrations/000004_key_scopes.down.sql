-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if tables are already dropped or database in unexpected state.
DROP TABLE IF EXISTS key_scope_secrets;
DROP TABLE IF EXISTS key_scopes;
