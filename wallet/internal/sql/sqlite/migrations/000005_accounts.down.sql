-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if tables are already dropped or database is in unexpected state.
DROP TABLE IF EXISTS account_secrets;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS account_origins;
