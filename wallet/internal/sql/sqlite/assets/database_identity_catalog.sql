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
    ) AS populated,
    (
        SELECT
            count(*) = 4
            AND sum(
                name = 'id' AND upper(type) = 'INTEGER'
                AND "notnull" = 0 AND pk = 1
            ) = 1
            AND sum(
                name = 'genesis_hash' AND upper(type) = 'BLOB'
                AND "notnull" = 1 AND pk = 0
            ) = 1
            AND sum(
                name = 'network_magic' AND upper(type) = 'INTEGER'
                AND "notnull" = 1 AND pk = 0
            ) = 1
            AND sum(
                name = 'signet_challenge_digest' AND upper(type) = 'BLOB'
                AND "notnull" = 0 AND pk = 0
            ) = 1
        FROM pragma_table_info('btcwallet_database_identity')
    ) AS identity_readable;
