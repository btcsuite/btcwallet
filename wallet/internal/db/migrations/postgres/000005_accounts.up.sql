-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- Account origin lookup table - provides standardized descriptions for wallet
-- account origins. This is a reference table that maps the AccountOrigin enum
-- values used in Go code to their human-readable names.
CREATE TABLE account_origins (
    -- Primary key matching the Go AccountOrigin enum values.
    -- Using explicit IDs rather than auto-increment to ensure consistency
    -- with the Go enum and across SQLite/Postgres implementations.
    id SMALLINT PRIMARY KEY,

    -- Human-readable account origin description.
    description TEXT NOT NULL
);

-- Unique constraint on description to prevent duplicate entries.
-- This ensures referential integrity and enables efficient reverse lookups.
CREATE UNIQUE INDEX uidx_account_origins_description
ON account_origins (description);

-- Seed reference data matching the Go AccountOrigin enum constants.
-- These values are static and represent the account origin types.
-- IDs MUST match the iota values in wallet/internal/db/data_types.go.
INSERT INTO account_origins (id, description) VALUES
(0, 'derived'),   -- Derived from a hierarchical deterministic key.
(1, 'imported');  -- Imported from an external source.

-- Accounts table stores wallet accounts under each key scope (BIP32/BIP44
-- hierarchy). Each account represents either a derived HD account following
-- BIP44 derivation paths (m/purpose'/coin'/account') or an imported account
-- from an external source (e.g., hardware wallet, watch-only xpub).
--
-- The table supports both account types through nullable account_number:
-- - Derived accounts have sequential account_number values (0, 1, 2, ...)
-- - Imported accounts have NULL account_number (not part of BIP44 hierarchy)
CREATE TABLE accounts (
    -- DB ID of the account, primary key.
    id BIGSERIAL PRIMARY KEY,

    -- Reference to the key scope this account belongs to.
    scope_id BIGINT NOT NULL,

    -- Account number described in BIP44. NULL for imported accounts since they
    -- don't follow the BIP44 derivation path.
    account_number BIGINT,

    -- Human friendly name for the account.
    account_name TEXT NOT NULL,

    -- Reference to the origin of the account.
    origin_id SMALLINT NOT NULL,

    -- Defines if the account is watch-only.
    is_watch_only BOOLEAN NOT NULL,

    -- Master fingerprint is the fingerprint of the master pub key that created
    -- this account.
    master_fingerprint BIGINT,

    -- Encrypted public key for the account.
    encrypted_public_key BYTEA,

    -- Timestamp when the account was created. Automatically set by the database.
    created_at TIMESTAMP NOT NULL DEFAULT current_timestamp,

    -- Next index to use for external addresses (branch 0)
    next_external_index BIGINT NOT NULL DEFAULT 0,

    -- Next index to use for internal/change addresses (branch 1)
    next_internal_index BIGINT NOT NULL DEFAULT 0,

    -- External derivation index must be non-negative.
    CHECK (next_external_index >= 0),

    -- Internal derivation index must be non-negative.
    CHECK (next_internal_index >= 0),

    -- Foreign key constraints to key scope. Using ON DELETE RESTRICT to ensure
    -- that the key scope cannot be deleted if accounts still exist.
    FOREIGN KEY (scope_id) REFERENCES key_scopes (id) ON DELETE RESTRICT,

    -- Foreign key constraint to account origins. Using ON DELETE RESTRICT to
    -- ensure that the origin cannot be deleted if accounts still exist.
    FOREIGN KEY (origin_id) REFERENCES account_origins (id) ON DELETE RESTRICT
);

-- Index on foreign scope_id for faster lookups and joins.
CREATE INDEX idx_accounts_scope ON accounts (scope_id);

-- Unique partial index to prevent duplicate account numbers within the same
-- key scope. Only enforced for non-NULL account numbers (derived accounts).
-- Imported accounts have NULL account_number and are excluded from this
-- constraint.
CREATE UNIQUE INDEX uidx_accounts_scope_account_number
ON accounts (scope_id, account_number)
WHERE account_number IS NOT NULL;

-- Unique index to prevent duplicate account names within the same key scope.
CREATE UNIQUE INDEX uidx_accounts_scope_account_name
ON accounts (scope_id, account_name);

-- Account Secrets table to hold encrypted account-level secrets.
CREATE TABLE account_secrets (
    -- Reference to the account these keys belong to.
    account_id BIGINT NOT NULL,

    -- Encrypted private key for the account. Watch-only accounts may have
    -- no row in this table.
    encrypted_private_key BYTEA NOT NULL,

    -- Foreign key constraint to accounts. Using ON DELETE RESTRICT to ensure
    -- that the account cannot be deleted if secrets still exist.
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE RESTRICT
);

-- Unique index to ensure one-to-one relationship between account and its secrets.
CREATE UNIQUE INDEX uidx_account_secrets_account
ON account_secrets (account_id);
