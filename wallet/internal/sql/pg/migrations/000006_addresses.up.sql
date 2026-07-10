-- Addresses are keyed by SHA256(addressID), matching the legacy address and
-- used-address buckets without exposing the encoded address in plaintext.
CREATE TABLE addresses (
    wallet_id BIGINT NOT NULL,
    scope_id BIGINT NOT NULL,
    address_hash BYTEA NOT NULL CHECK (length(address_hash) = 32),
    account_number BIGINT NOT NULL
        CHECK (account_number BETWEEN 0 AND 4294967295),
    address_type SMALLINT NOT NULL CHECK (address_type BETWEEN 0 AND 4),
    added_at BIGINT NOT NULL CHECK (added_at >= 0),
    sync_status SMALLINT NOT NULL CHECK (sync_status IN (0, 1, 2)),
    branch BIGINT CHECK (branch BETWEEN 0 AND 4294967295),
    address_index BIGINT CHECK (address_index BETWEEN 0 AND 4294967295),
    encrypted_pub_key BYTEA,
    encrypted_priv_key BYTEA,
    encrypted_hash BYTEA,
    encrypted_script BYTEA,
    witness_version SMALLINT CHECK (witness_version BETWEEN 0 AND 255),
    is_secret_script BOOLEAN,
    used BOOLEAN NOT NULL DEFAULT FALSE,
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
CREATE FUNCTION assert_address_used_is_monotonic() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.used AND NOT NEW.used THEN
        RAISE EXCEPTION 'address used state cannot be cleared'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_addresses_used_is_monotonic
BEFORE UPDATE OF used ON addresses
FOR EACH ROW
EXECUTE FUNCTION assert_address_used_is_monotonic();
