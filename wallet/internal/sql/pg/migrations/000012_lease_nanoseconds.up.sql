-- Lease expirations in migration 000009 were stored as Unix seconds. Convert
-- existing rows before runtime code starts comparing nanosecond timestamps.
UPDATE utxo_leases
SET expires_unix = expires_unix * 1000000000;
