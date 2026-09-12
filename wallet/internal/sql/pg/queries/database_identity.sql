-- name: InspectDatabaseIdentityNamespace :one
-- InspectDatabaseIdentityNamespace permits first adoption only when the fixed
-- schema is absent and validates that a marker has the readable column shape.
WITH identity_relation AS (
    SELECT c.oid
    FROM pg_catalog.pg_class AS c
    INNER JOIN pg_catalog.pg_namespace AS n ON c.relnamespace = n.oid
    WHERE
        n.nspname = 'btcwallet'
        AND c.relname = 'database_identity'
        AND c.relkind = 'r'
)

SELECT
    exists(
        SELECT 1
        FROM pg_catalog.pg_namespace AS n
        WHERE n.nspname = 'btcwallet'
    ) AS schema_exists,
    exists(
        SELECT 1 FROM identity_relation
    ) AS identity_exists,
    coalesce(
        (
            SELECT
                array_agg(a.attname::TEXT ORDER BY a.attnum) = ARRAY[
                    'id',
                    'genesis_hash',
                    'network_magic',
                    'signet_challenge_digest'
                ]
                AND array_agg(a.atttypid ORDER BY a.attnum) = ARRAY[
                    'pg_catalog.int2'::REGTYPE::OID,
                    'pg_catalog.bytea'::REGTYPE::OID,
                    'pg_catalog.int8'::REGTYPE::OID,
                    'pg_catalog.bytea'::REGTYPE::OID
                ]
                AND array_agg(a.attnotnull ORDER BY a.attnum) = ARRAY[
                    TRUE, TRUE, TRUE, FALSE
                ]
            FROM identity_relation AS r
            INNER JOIN pg_catalog.pg_attribute AS a ON r.oid = a.attrelid
            WHERE a.attnum > 0 AND NOT a.attisdropped
        ),
        FALSE
    )::BOOLEAN AS identity_readable;

-- name: InsertDatabaseIdentity :exec
-- InsertDatabaseIdentity writes the only permitted row after the namespace
-- probe proves the fixed schema is absent and safe to claim.
INSERT INTO btcwallet.database_identity (
    id,
    genesis_hash,
    network_magic,
    signet_challenge_digest
) VALUES (
    1,
    sqlc.arg('genesis_hash'),
    sqlc.arg('network_magic'),
    sqlc.narg('signet_challenge_digest')
);

-- name: CountDatabaseIdentities :one
-- CountDatabaseIdentities verifies the singleton invariant before any stored
-- values are trusted by startup.
SELECT count(*) AS row_count
FROM btcwallet.database_identity;

-- name: GetDatabaseIdentity :one
-- GetDatabaseIdentity reads the canonical row only after startup has proved
-- that exactly one row exists.
SELECT
    genesis_hash,
    network_magic,
    signet_challenge_digest
FROM btcwallet.database_identity
WHERE id = 1;
