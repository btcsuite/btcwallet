-- Key Scopes table to store different key scopes (BIP standards) for each
-- wallet.
--
-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.
CREATE TABLE key_scopes (
    -- DB ID of the key scope, primary key. Only used for DB level relations.
    id BIGSERIAL PRIMARY KEY,

    -- Reference to the wallet this key scope belongs to.
    wallet_id BIGINT NOT NULL,

    -- Indicates the BIP standard for the key scope. This is typically will be
    -- 84h or 1017h.
    purpose BIGINT NOT NULL,

    -- Indicates the coin type for the key scope. This is typically 0 for BTC.
    coin_type BIGINT NOT NULL,

    -- Encrypted key used to derive public keys for this scope in imported
    -- accounts.
    encrypted_coin_pub_key BYTEA,

    -- Reference to the address type used for internal/change addresses.
    internal_type_id SMALLINT NOT NULL,

    -- Reference to the address type used for external/receiving addresses.
    external_type_id SMALLINT NOT NULL,

    -- Foreign key constraint to wallet. Using ON DELETE RESTRICT to ensure
    -- that the wallet cannot be deleted if key scopes still exist.
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT,

    -- Foreign key constraints to address types. Using ON DELETE RESTRICT to ensure
    -- that the address types cannot be deleted if key scopes still exist.
    FOREIGN KEY (internal_type_id) REFERENCES address_types (id) ON DELETE RESTRICT,
    FOREIGN KEY (external_type_id) REFERENCES address_types (id) ON DELETE RESTRICT
);

-- Unique index to prevent duplicate key scopes for the same wallet.
CREATE UNIQUE INDEX uidx_key_scopes_wallet_purpose_coin
ON key_scopes (wallet_id, purpose, coin_type);

-- Unique index to support composite foreign keys scoped by wallet ownership.
CREATE UNIQUE INDEX uidx_key_scopes_wallet_id_id ON key_scopes (wallet_id, id);

-- Key Scope Secrets table to hold encrypted coin-type secrets for spendable
-- scopes.
-- Separated from the main key_scopes table for security and access pattern
-- isolation. Watch-only scopes are represented by having no row in this table.
CREATE TABLE key_scope_secrets (
    -- Reference to the key scope these keys belong to. Also serves as the
    -- primary key, enforcing one-to-one relationship.
    scope_id BIGINT PRIMARY KEY,

    -- Encrypted key used to derive private keys for this scope.
    -- NOT NULL enforces that only spendable scopes have a row in this table.
    encrypted_coin_priv_key BYTEA NOT NULL,

    -- Foreign key constraint to key_scopes. Using ON DELETE RESTRICT to ensure
    -- that the key scope cannot be deleted if secrets still exist.
    FOREIGN KEY (scope_id) REFERENCES key_scopes (id) ON DELETE RESTRICT
);

-- Enforce the watch-only key-scope secret invariant at the database boundary.
-- Watch-only wallets may keep a scope row for public derivation metadata, but
-- the matching key_scope_secrets row must not carry coin private key material.
CREATE FUNCTION assert_watch_only_key_scope_secrets() RETURNS TRIGGER AS $$
DECLARE
    wallet_is_watch_only BOOLEAN;
BEGIN
    SELECT w.is_watch_only INTO wallet_is_watch_only
    FROM key_scopes AS ks
    INNER JOIN wallets AS w ON w.id = ks.wallet_id
    WHERE ks.id = NEW.scope_id;

    IF wallet_is_watch_only THEN
        RAISE EXCEPTION 'watch-only key scopes cannot store coin private keys'
            USING ERRCODE = '23514'; -- check_violation
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_assert_watch_only_key_scope_secrets_insert
BEFORE INSERT ON key_scope_secrets
FOR EACH ROW
EXECUTE FUNCTION assert_watch_only_key_scope_secrets();

CREATE TRIGGER trg_assert_watch_only_key_scope_secrets_update
BEFORE UPDATE ON key_scope_secrets
FOR EACH ROW
EXECUTE FUNCTION assert_watch_only_key_scope_secrets();
