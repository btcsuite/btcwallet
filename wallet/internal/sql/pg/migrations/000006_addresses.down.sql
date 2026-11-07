-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if tables are already dropped or database is in unexpected state.
DROP TRIGGER IF EXISTS trg_assert_watch_only_address_secrets_insert ON address_secrets;
DROP TRIGGER IF EXISTS trg_assert_watch_only_address_secrets_update ON address_secrets;
DROP TRIGGER IF EXISTS trg_assert_derived_address_parent_insert ON derived_addresses;
DROP TRIGGER IF EXISTS trg_reject_derived_address_update ON derived_addresses;
DROP TRIGGER IF EXISTS trg_assert_address_identity_immutable ON addresses;
DROP FUNCTION IF EXISTS assert_watch_only_address_secrets();
DROP FUNCTION IF EXISTS reject_derived_address_update();
DROP FUNCTION IF EXISTS assert_derived_address_parent();
DROP FUNCTION IF EXISTS assert_address_identity_immutable();
DROP TABLE IF EXISTS address_secrets;
DROP TABLE IF EXISTS derived_addresses;
DROP TABLE IF EXISTS addresses;
