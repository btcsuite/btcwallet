-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if tables are already dropped or database is in unexpected state.
DROP TRIGGER IF EXISTS trg_assert_watch_only_address_secrets_insert;
DROP TRIGGER IF EXISTS trg_assert_watch_only_address_secrets_update;
DROP TRIGGER IF EXISTS trg_addresses_imported_key_count_insert;
DROP TRIGGER IF EXISTS trg_addresses_imported_key_count_delete;
DROP INDEX IF EXISTS idx_addresses_account_id;
DROP TABLE IF EXISTS address_secrets;
DROP TABLE IF EXISTS addresses;
