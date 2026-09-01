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
-- GetDatabaseIdentity reads the canonical row only after startup has proved
-- that exactly one row exists.
SELECT
    genesis_hash,
    network_magic,
    signet_challenge_digest
FROM btcwallet_database_identity
WHERE id = 1;
