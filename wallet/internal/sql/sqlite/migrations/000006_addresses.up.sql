-- Addresses are keyed by SHA256(addressID), matching the legacy address and
-- used-address buckets without exposing the encoded address in plaintext.
CREATE TABLE addresses (
    wallet_id INTEGER NOT NULL,
    scope_id INTEGER NOT NULL,
    address_hash BLOB NOT NULL CHECK (length(address_hash) = 32),
    account_number INTEGER NOT NULL
        CHECK (account_number BETWEEN 0 AND 4294967295),
    address_type INTEGER NOT NULL CHECK (address_type BETWEEN 0 AND 4),
    added_at INTEGER NOT NULL CHECK (added_at >= 0),
    sync_status INTEGER NOT NULL CHECK (sync_status IN (0, 1, 2)),
    branch INTEGER CHECK (branch BETWEEN 0 AND 4294967295),
    address_index INTEGER CHECK (address_index BETWEEN 0 AND 4294967295),
    encrypted_pub_key BLOB,
    encrypted_priv_key BLOB,
    encrypted_hash BLOB,
    encrypted_script BLOB,
    witness_version INTEGER CHECK (witness_version BETWEEN 0 AND 255),
    is_secret_script BOOLEAN
        CHECK (is_secret_script IS NULL OR is_secret_script IN (FALSE, TRUE)),
    used BOOLEAN NOT NULL DEFAULT FALSE CHECK (used IN (FALSE, TRUE)),
    PRIMARY KEY (wallet_id, scope_id, address_hash),
    FOREIGN KEY (scope_id, account_number, wallet_id)
        REFERENCES accounts (scope_id, account_number, wallet_id)
        ON DELETE RESTRICT,
    CHECK (
        (address_type = 0
            AND branch IS NOT NULL
            AND address_index IS NOT NULL
            AND encrypted_pub_key IS NULL
            AND encrypted_priv_key IS NULL
            AND encrypted_hash IS NULL
            AND encrypted_script IS NULL
            AND witness_version IS NULL
            AND is_secret_script IS NULL)
        OR (address_type = 1
            AND branch IS NULL
            AND address_index IS NULL
            AND encrypted_pub_key IS NOT NULL
            AND encrypted_hash IS NULL
            AND encrypted_script IS NULL
            AND witness_version IS NULL
            AND is_secret_script IS NULL)
        OR (address_type = 2
            AND branch IS NULL
            AND address_index IS NULL
            AND encrypted_pub_key IS NULL
            AND encrypted_priv_key IS NULL
            AND encrypted_hash IS NOT NULL
            AND witness_version IS NULL
            AND is_secret_script IS NULL)
        OR (address_type IN (3, 4)
            AND branch IS NULL
            AND address_index IS NULL
            AND encrypted_pub_key IS NULL
            AND encrypted_priv_key IS NULL
            AND encrypted_hash IS NOT NULL
            AND witness_version IS NOT NULL
            AND is_secret_script IS NOT NULL)
    )
);

CREATE INDEX idx_addresses_account
ON addresses (scope_id, account_number, address_hash);

-- The used bit is sticky, as it is in the legacy used-address bucket.
CREATE TRIGGER trg_addresses_used_is_monotonic
BEFORE UPDATE OF used ON addresses
FOR EACH ROW
WHEN old.used = TRUE AND new.used = FALSE
BEGIN
    SELECT raise(ABORT, 'address used state cannot be cleared');
END;
