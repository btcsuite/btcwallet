-- Key Scopes table to store different key scopes (BIP standards) for each
-- wallet.
--
-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.
CREATE TABLE key_scopes (
    -- DB ID of the key scope, primary key. Only used for DB level relations.
    id INTEGER PRIMARY KEY,

    -- Reference to the wallet this key scope belongs to.
    wallet_id INTEGER NOT NULL,

    -- Indicates the BIP standard for the key scope. This is typically will be
    -- 84h or 1017h.
    purpose INTEGER NOT NULL,

    -- Indicates the coin type for the key scope. This is typically 0 for BTC.
    coin_type INTEGER NOT NULL,

    -- Encrypted key used to derive public keys for this scope in imported
    -- accounts.
    encrypted_coin_pub_key BLOB,

    -- Reference to the address type used for internal/change addresses.
    internal_type_id INTEGER NOT NULL,

    -- Reference to the address type used for external/receiving addresses.
    external_type_id INTEGER NOT NULL,

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

-- Enforce that wallet ownership chosen at key-scope creation time remains
-- immutable. This closes the database-boundary hole where a raw update could
-- reparent an existing scope into another wallet after insert.
CREATE TRIGGER trg_assert_key_scope_wallet_id_immutable
BEFORE UPDATE OF wallet_id ON key_scopes
FOR EACH ROW
WHEN new.wallet_id != old.wallet_id
BEGIN
    SELECT raise(ABORT, 'key scope wallet_id cannot be changed after creation');
END;

-- Key Scope Secrets table to hold encrypted coin-type secrets for spendable
-- scopes.
-- Separated from the main key_scopes table for security and access pattern
-- isolation. Watch-only scopes are represented by having no row in this table.
CREATE TABLE key_scope_secrets (
    -- Reference to the key scope these keys belong to. Also serves as the
    -- primary key, enforcing one-to-one relationship.
    scope_id INTEGER PRIMARY KEY,

    -- Encrypted key used to derive private keys for this scope.
    -- NOT NULL enforces that only spendable scopes have a row in this table.
    encrypted_coin_priv_key BLOB NOT NULL,

    -- Foreign key constraint to key_scopes. Using ON DELETE RESTRICT to ensure
    -- that the key scope cannot be deleted if secrets still exist.
    FOREIGN KEY (scope_id) REFERENCES key_scopes (id) ON DELETE RESTRICT
);

-- Enforce the watch-only key-scope secret invariant at the database boundary.
-- Watch-only wallets may keep a scope row for public derivation metadata, but
-- the matching key_scope_secrets row must not carry coin private key material.
CREATE TRIGGER trg_assert_watch_only_key_scope_secrets_insert
BEFORE INSERT ON key_scope_secrets
FOR EACH ROW
BEGIN
    SELECT raise(ABORT, 'watch-only key scopes cannot store coin private keys')
    WHERE
        EXISTS (
            SELECT 1
            FROM key_scopes AS ks
            INNER JOIN wallets AS w ON ks.wallet_id = w.id
            WHERE
                ks.id = new.scope_id
                AND w.is_watch_only
        );
END;

CREATE TRIGGER trg_assert_watch_only_key_scope_secrets_update
BEFORE UPDATE ON key_scope_secrets
FOR EACH ROW
BEGIN
    SELECT raise(ABORT, 'watch-only key scopes cannot store coin private keys')
    WHERE
        EXISTS (
            SELECT 1
            FROM key_scopes AS ks
            INNER JOIN wallets AS w ON ks.wallet_id = w.id
            WHERE
                ks.id = new.scope_id
                AND w.is_watch_only
        );
END;
