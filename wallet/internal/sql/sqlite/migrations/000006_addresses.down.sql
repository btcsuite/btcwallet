-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if tables are already dropped or database is in unexpected state.
DROP TRIGGER IF EXISTS trg_assert_watch_only_address_secrets_insert;
DROP TRIGGER IF EXISTS trg_assert_watch_only_address_secrets_update;
DROP TRIGGER IF EXISTS trg_assert_address_wallet_id_immutable;
DROP TRIGGER IF EXISTS trg_assert_derived_address_parent_insert;
DROP TRIGGER IF EXISTS trg_reject_derived_address_update;
DROP INDEX IF EXISTS idx_addresses_account_id;
DROP TABLE IF EXISTS address_secrets;
DROP TABLE IF EXISTS derived_addresses;
DROP TABLE IF EXISTS addresses;
