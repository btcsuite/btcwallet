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

-- Key Scope Secrets table to hold encrypted coin-type secrets for each scope.
-- Separated from the main key_scopes table for security and access pattern isolation.
-- Watch-only scopes may have no corresponding row in this table or have NULL
-- encrypted_coin_priv_key.
CREATE TABLE key_scope_secrets (
    -- Reference to the key scope these keys belong to. Also serves as the
    -- primary key, enforcing one-to-one relationship.
    scope_id BIGINT PRIMARY KEY,

    -- Encrypted key used to derive private keys for this scope.
    -- NULL for watch-only key scopes.
    encrypted_coin_priv_key BYTEA,

    -- Foreign key constraint to key_scopes. Using ON DELETE RESTRICT to ensure
    -- that the key scope cannot be deleted if secrets still exist.
    FOREIGN KEY (scope_id) REFERENCES key_scopes (id) ON DELETE RESTRICT
);
