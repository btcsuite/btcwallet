-- The fixed schema and singleton table bind PostgreSQL wallet objects to one
-- Bitcoin network before ordinary migrations are allowed to run.
CREATE SCHEMA btcwallet;

CREATE TABLE btcwallet.database_identity (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    genesis_hash BYTEA NOT NULL CHECK (length(genesis_hash) = 32),
    network_magic BIGINT NOT NULL CHECK (
        network_magic BETWEEN 0 AND 4294967295
    ),
    signet_challenge_digest BYTEA CHECK (
        signet_challenge_digest IS NULL
        OR length(signet_challenge_digest) = 32
    )
);
