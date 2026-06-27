-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- Accounts table stores wallet-level HD account identity under each key scope.
-- Wallet-derived BIP44 account numbers live in derived_accounts; imported xpub
-- accounts have an accounts row without a derived_accounts child.
CREATE TABLE accounts (
    -- DB ID of the account, primary key.
    id BIGSERIAL PRIMARY KEY,

    -- Reference to the wallet this account belongs to.
    wallet_id BIGINT NOT NULL,

    -- Reference to the key scope this account belongs to.
    scope_id BIGINT NOT NULL,

    -- Human friendly name for the account.
    account_name TEXT NOT NULL,

    -- Shape marker. TRUE means this account must have a derived_accounts child
    -- row with a wallet-derived BIP44 account number. Imported xpub accounts
    -- leave this FALSE.
    is_derived BOOLEAN NOT NULL,

    -- Master fingerprint is the fingerprint of the master pub key that created
    -- this account.
    master_fingerprint BIGINT,

    -- Public key for the account. Stored plaintext per ADR 0009
    -- (docs/developer/adr/0009-single-passphrase-encryption.md).
    public_key BYTEA,

    -- Timestamp when the account was created. Automatically set by the database
    -- in UTC.
    created_at TIMESTAMP NOT NULL DEFAULT (current_timestamp AT TIME ZONE 'UTC'),

    -- Next index to use for external addresses (branch 0).
    next_external_index BIGINT NOT NULL DEFAULT 0,

    -- Next index to use for internal/change addresses (branch 1).
    next_internal_index BIGINT NOT NULL DEFAULT 0,

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
    account_id BIGINT PRIMARY KEY,

    -- Duplicate of accounts.scope_id for uniqueness and drift checks.
    scope_id BIGINT NOT NULL,

    -- BIP44 account number allocated by the wallet for this scope.
    account_number BIGINT NOT NULL,

    -- Account numbers must be non-negative.
    CHECK (account_number >= 0),

    -- Foreign key constraint to accounts. Using ON DELETE RESTRICT to ensure
    -- that the account cannot be deleted if derived identity still exists.
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE RESTRICT,

    -- Composite foreign key to ensure duplicated scope_id matches the parent
    -- account row.
    FOREIGN KEY (account_id, scope_id)
    REFERENCES accounts (id, scope_id) ON DELETE RESTRICT
);

-- Unique index to prevent duplicate account numbers within the same key scope.
CREATE UNIQUE INDEX uidx_derived_accounts_scope_account_number
ON derived_accounts (scope_id, account_number);

-- Enforce that structural account identity fields chosen at account creation
-- time remain immutable.
CREATE FUNCTION assert_account_identity_immutable() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.wallet_id IS DISTINCT FROM OLD.wallet_id
        OR NEW.scope_id IS DISTINCT FROM OLD.scope_id
        OR NEW.is_derived IS DISTINCT FROM OLD.is_derived THEN

        RAISE EXCEPTION 'account identity cannot be changed after creation'
            USING ERRCODE = '23514'; -- check_violation
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_assert_account_identity_immutable
BEFORE UPDATE OF id, wallet_id, scope_id, is_derived ON accounts
FOR EACH ROW
EXECUTE FUNCTION assert_account_identity_immutable();

-- Enforce that only accounts marked as derived can receive BIP44 account-number
-- rows.
CREATE FUNCTION assert_derived_account_parent() RETURNS TRIGGER AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM accounts AS a
        WHERE
            a.id = NEW.account_id
            AND a.scope_id = NEW.scope_id
            AND a.is_derived
    ) THEN

        RAISE EXCEPTION 'derived account parent must be marked derived'
            USING ERRCODE = '23514'; -- check_violation
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_assert_derived_account_parent_insert
BEFORE INSERT ON derived_accounts
FOR EACH ROW
EXECUTE FUNCTION assert_derived_account_parent();

-- Derived account identity rows are allocated once and never retargeted.
CREATE FUNCTION reject_derived_account_update() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'derived account identity cannot be changed after creation'
        USING ERRCODE = '23514'; -- check_violation
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_reject_derived_account_update
BEFORE UPDATE ON derived_accounts
FOR EACH ROW
EXECUTE FUNCTION reject_derived_account_update();

-- Account Secrets table to hold encrypted account-level secrets.
CREATE TABLE account_secrets (
    -- Reference to the account these keys belong to. Also serves as the
    -- primary key, enforcing one-to-one relationship.
    account_id BIGINT PRIMARY KEY,

    -- Encrypted private key for the account. Watch-only accounts may have
    -- no row in this table.
    encrypted_private_key BYTEA NOT NULL,

    -- Foreign key constraint to accounts. Using ON DELETE RESTRICT to ensure
    -- that the account cannot be deleted if secrets still exist.
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE RESTRICT
);

-- Enforce the watch-only account secret invariant at the database boundary.
-- Accounts in watch-only wallets must not store account-level private key
-- material.
--
-- Note: Unlike address_secrets.encrypted_priv_key (which is nullable for
-- HD-derived addresses), account_secrets.encrypted_private_key is NOT NULL.
-- This means any row in account_secrets necessarily represents private key
-- material, so we reject all inserts/updates for watch-only parents without
-- needing to check column nullability first.
CREATE FUNCTION assert_watch_only_account_secrets() RETURNS TRIGGER AS $$
DECLARE
    wallet_is_watch_only BOOLEAN;
BEGIN
    SELECT w.is_watch_only INTO wallet_is_watch_only
    FROM accounts AS a
    INNER JOIN wallets AS w ON w.id = a.wallet_id
    WHERE a.id = NEW.account_id;

    IF wallet_is_watch_only THEN
        RAISE EXCEPTION 'watch-only wallet accounts cannot store account secrets'
            USING ERRCODE = '23514'; -- check_violation
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_assert_watch_only_account_secrets_insert
BEFORE INSERT ON account_secrets
FOR EACH ROW
EXECUTE FUNCTION assert_watch_only_account_secrets();

CREATE TRIGGER trg_assert_watch_only_account_secrets_update
BEFORE UPDATE ON account_secrets
FOR EACH ROW
EXECUTE FUNCTION assert_watch_only_account_secrets();
