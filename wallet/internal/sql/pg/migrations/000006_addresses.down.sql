-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if tables are already dropped or database is in unexpected state.
DROP TRIGGER IF EXISTS trg_addresses_imported_key_count_insert ON addresses;
DROP TRIGGER IF EXISTS trg_addresses_imported_key_count_delete ON addresses;
DROP FUNCTION IF EXISTS sync_account_imported_key_count_insert();
DROP FUNCTION IF EXISTS sync_account_imported_key_count_delete();
DROP INDEX IF EXISTS idx_addresses_account_id;
DROP TABLE IF EXISTS address_secrets;
DROP TABLE IF EXISTS addresses;
