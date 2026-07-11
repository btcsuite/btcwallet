DROP TRIGGER IF EXISTS trg_addresses_used_is_monotonic ON addresses;
DROP FUNCTION IF EXISTS assert_address_used_is_monotonic();
DROP TABLE IF EXISTS addresses;
