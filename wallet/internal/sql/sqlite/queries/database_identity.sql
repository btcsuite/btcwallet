-- name: InsertDatabaseIdentity :exec
-- InsertDatabaseIdentity writes the only permitted row after catalog checks
-- prove that an unmarked SQLite file is empty and safe to claim.
INSERT INTO btcwallet_database_identity (
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
FROM btcwallet_database_identity;

-- name: GetDatabaseIdentity :one
-- GetDatabaseIdentity reads only a canonical SQLite value tuple so dynamic
-- storage classes and out-of-range integers become a malformed missing row.
SELECT
    genesis_hash,
    network_magic,
    signet_challenge_digest
FROM btcwallet_database_identity
WHERE
    id = 1
    AND typeof(genesis_hash) = 'blob'
    AND length(genesis_hash) = 32
    AND typeof(network_magic) = 'integer'
    AND network_magic BETWEEN 0 AND 4294967295
    AND (
        signet_challenge_digest IS NULL
        OR (
            typeof(signet_challenge_digest) = 'blob'
            AND length(signet_challenge_digest) = 32
        )
    );
