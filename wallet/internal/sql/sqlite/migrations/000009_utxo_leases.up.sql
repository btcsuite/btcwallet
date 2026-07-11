-- Output leases retain the legacy outpoint key and are deliberately
-- independent of credit lifetime.
CREATE TABLE utxo_leases (
    wallet_id INTEGER NOT NULL,
    tx_hash BLOB NOT NULL CHECK (length(tx_hash) = 32),
    output_index INTEGER NOT NULL
        CHECK (output_index BETWEEN 0 AND 4294967295),
    lock_id BLOB NOT NULL CHECK (length(lock_id) = 32),
    expires_unix INTEGER NOT NULL,
    PRIMARY KEY (wallet_id, tx_hash, output_index),
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT
);

CREATE INDEX idx_utxo_leases_expiry
ON utxo_leases (wallet_id, expires_unix, tx_hash, output_index);
