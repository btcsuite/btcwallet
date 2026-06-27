-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- Accounts table stores wallet-level HD account identity under each key scope.
-- Wallet-derived BIP44 account numbers live in derived_accounts; imported xpub
-- accounts have an accounts row without a derived_accounts child.
CREATE TABLE accounts (
    -- DB ID of the account, primary key.
    id INTEGER PRIMARY KEY,

    -- Reference to the wallet this account belongs to.
    wallet_id INTEGER NOT NULL,

    -- Reference to the key scope this account belongs to.
    scope_id INTEGER NOT NULL,

    -- Human friendly name for the account.
    account_name TEXT NOT NULL,

    -- Shape marker. TRUE means this account must have a derived_accounts child
    -- row with a wallet-derived BIP44 account number. Imported xpub accounts
    -- leave this FALSE.
    is_derived BOOLEAN NOT NULL,

    -- Master fingerprint is the fingerprint of the master pub key that created
    -- this account.
    master_fingerprint INTEGER,

    -- Public key for the account. Stored plaintext per ADR 0009
    -- (docs/developer/adr/0009-single-passphrase-encryption.md).
    public_key BLOB,

    -- Timestamp when the account was created. Automatically set by the database.
    created_at DATETIME NOT NULL DEFAULT current_timestamp,

    -- Next index to use for external addresses (branch 0).
    next_external_index INTEGER NOT NULL DEFAULT 0,

    -- Next index to use for internal/change addresses (branch 1).
    next_internal_index INTEGER NOT NULL DEFAULT 0,

    -- Shape marker must be boolean.
    CHECK (is_derived IN (0, 1)),

    -- External derivation index must be non-negative.
    CHECK (next_external_index >= 0),

    -- Internal derivation index must be non-negative.
    CHECK (next_internal_index >= 0),

    -- Composite foreign key to key scopes. This ensures scope_id belongs to
    -- the same wallet_id as the account row. Wallet ownership is transitively
    -- enforced through key_scopes, which has its own FK to wallets. Using ON
    -- DELETE RESTRICT to ensure that the wallet/scope cannot be deleted if
    -- accounts still exist.
    FOREIGN KEY (wallet_id, scope_id)
    REFERENCES key_scopes (wallet_id, id) ON DELETE RESTRICT
);

-- Index on foreign scope_id for faster lookups and joins.
CREATE INDEX idx_accounts_scope ON accounts (scope_id);

-- Unique index to prevent duplicate account names within the same key scope.
CREATE UNIQUE INDEX uidx_accounts_wallet_scope_account_name
ON accounts (wallet_id, scope_id, account_name);

-- Unique indexes to support composite child-table foreign keys.
CREATE UNIQUE INDEX uidx_accounts_id_wallet_scope
ON accounts (id, wallet_id, scope_id);

CREATE UNIQUE INDEX uidx_accounts_id_scope
ON accounts (id, scope_id);

-- Derived Accounts table stores wallet-derived BIP44 account numbers.
CREATE TABLE derived_accounts (
    -- Reference to the parent account. Also serves as the primary key,
    -- enforcing one derived account row per account.
    account_id INTEGER PRIMARY KEY,

    -- Duplicate of accounts.scope_id for uniqueness and drift checks.
    scope_id INTEGER NOT NULL,

    -- BIP44 account number allocated by the wallet for this scope.
    account_number INTEGER NOT NULL,

    -- Account numbers must be non-negative.
    CHECK (account_number >= 0),

    -- Foreign key constraint to accounts. Using ON DELETE RESTRICT to ensure
    -- that the account cannot be deleted if derived identity still exists.
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE RESTRICT,

    -- Composite foreign key to ensure duplicated scope_id matches the parent
    -- account row.
    FOREIGN KEY (account_id, scope_id)
    REFERENCES accounts (id, scope_id) ON DELETE RESTRICT
) WITHOUT ROWID;

-- Unique index to prevent duplicate account numbers within the same key scope.
CREATE UNIQUE INDEX uidx_derived_accounts_scope_account_number
ON derived_accounts (scope_id, account_number);

-- Enforce that structural account identity fields chosen at account creation
-- time remain immutable.
CREATE TRIGGER trg_assert_account_identity_immutable
BEFORE UPDATE ON accounts
FOR EACH ROW
WHEN
    new.id != old.id
    OR new.wallet_id != old.wallet_id
    OR new.scope_id != old.scope_id
    OR new.is_derived != old.is_derived
BEGIN
    SELECT raise(ABORT, 'account identity cannot be changed after creation');
END;

-- Enforce that only accounts marked as derived can receive BIP44 account-number
-- rows.
CREATE TRIGGER trg_assert_derived_account_parent_insert
BEFORE INSERT ON derived_accounts
FOR EACH ROW
BEGIN
    SELECT raise(ABORT, 'derived account parent must be marked derived')
    WHERE NOT EXISTS (
        SELECT 1
        FROM accounts AS a
        WHERE
            a.id = new.account_id
            AND a.scope_id = new.scope_id
            AND a.is_derived
    );
END;

-- Derived account identity rows are allocated once and never retargeted.
CREATE TRIGGER trg_reject_derived_account_update
BEFORE UPDATE ON derived_accounts
FOR EACH ROW
BEGIN
    SELECT raise(
        ABORT, 'derived account identity cannot be changed after creation'
    );
END;

-- Account Secrets table to hold encrypted account-level secrets.
CREATE TABLE account_secrets (
    -- Reference to the account these keys belong to. Also serves as the
    -- primary key, enforcing one-to-one relationship.
    account_id INTEGER PRIMARY KEY,

    -- Encrypted private key for the account. Watch-only accounts may have
    -- no row in this table.
    encrypted_private_key BLOB NOT NULL,

    -- Foreign key constraint to accounts. Using ON DELETE RESTRICT to ensure
    -- that the account cannot be deleted if secrets still exist.
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE RESTRICT
) WITHOUT ROWID;

-- Enforce the watch-only account secret invariant at the database boundary.
-- Accounts in watch-only wallets must not store account-level private key
-- material.
--
-- Note: Unlike address_secrets.encrypted_priv_key (which is nullable for
-- HD-derived addresses), account_secrets.encrypted_private_key is NOT NULL.
-- This means any row in account_secrets necessarily represents private key
-- material, so we reject all inserts/updates for watch-only parents without
-- needing to check column nullability first.
CREATE TRIGGER trg_assert_watch_only_account_secrets_insert
BEFORE INSERT ON account_secrets
FOR EACH ROW
BEGIN
    SELECT raise(ABORT, 'watch-only accounts cannot store account secrets')
    WHERE (
        SELECT w.is_watch_only
        FROM accounts AS a
        INNER JOIN wallets AS w ON a.wallet_id = w.id
        WHERE a.id = new.account_id
    );
END;

CREATE TRIGGER trg_assert_watch_only_account_secrets_update
BEFORE UPDATE ON account_secrets
FOR EACH ROW
BEGIN
    SELECT raise(ABORT, 'watch-only accounts cannot store account secrets')
    WHERE (
        SELECT w.is_watch_only
        FROM accounts AS a
        INNER JOIN wallets AS w ON a.wallet_id = w.id
        WHERE a.id = new.account_id
    );
END;
