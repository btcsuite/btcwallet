-- The singleton identity table binds the SQLite file to one Bitcoin network
-- before ordinary migrations are allowed to create wallet data.
CREATE TABLE btcwallet_database_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    genesis_hash BLOB NOT NULL CHECK (length(genesis_hash) = 32),
    network_magic INTEGER NOT NULL CHECK (
        network_magic BETWEEN 0 AND 4294967295
    ),
    signet_challenge_digest BLOB CHECK (
        signet_challenge_digest IS NULL
        OR length(signet_challenge_digest) = 32
    )
);
