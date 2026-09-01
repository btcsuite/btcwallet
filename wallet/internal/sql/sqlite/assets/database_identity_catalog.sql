-- This catalog probe distinguishes a new SQLite file from populated storage
-- that btcwallet must not claim. GLOB keeps the underscore in SQLite's
-- internal sqlite_ prefix literal rather than treating it as a wildcard.
SELECT
    exists(
        SELECT 1
        FROM sqlite_schema
        WHERE
            type = 'table'
            AND name = 'btcwallet_database_identity'
    ) AS identity_exists,
    exists(
        SELECT 1
        FROM sqlite_schema
        WHERE name NOT GLOB 'sqlite_*'
    ) AS populated;
