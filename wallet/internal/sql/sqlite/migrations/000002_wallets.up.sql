-- Wallet metadata and related state tables.
--
-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.
CREATE TABLE wallets (
    -- DB ID of the wallet, primary key. Only used for DB level relations.
    id INTEGER PRIMARY KEY,

    -- Human friendly name for the wallet.
    wallet_name TEXT NOT NULL,

    -- Defines if the wallet was imported, all its accounts would also be imported.
    is_imported BOOLEAN NOT NULL,

    -- Version of the wallet manager that created this wallet.
    manager_version INTEGER NOT NULL,

    -- Defines if the wallet is a watch-only wallet.
    is_watch_only BOOLEAN NOT NULL,

    -- Master HD public key of the wallet. NULL for certain wallet types that
    -- don't store extended public keys.
    master_hd_pub_key BLOB
);

-- Unique index to prevent duplicate wallet names.
CREATE UNIQUE INDEX uidx_wallets_name ON wallets (wallet_name);

-- Enforce that the watch-only status chosen at wallet creation time remains
-- immutable. This closes the database-boundary hole where a raw wallet update
-- could silently bypass the secret-table triggers by flipping the parent
-- wallet between watch-only and spendable after insert.
CREATE TRIGGER trg_assert_wallet_is_watch_only_immutable
BEFORE UPDATE OF is_watch_only ON wallets
FOR EACH ROW
WHEN new.is_watch_only != old.is_watch_only
BEGIN
    SELECT raise(ABORT, 'wallet is_watch_only cannot be changed after creation');
END;

-- Wallet Secrets table to store rarely accessed, highly sensitive encrypted
-- material with a strict one-to-one relationship with the wallets table.
-- Separated from the main wallets table for security and access pattern isolation.
-- Watch-only wallets may have no corresponding row in this table or may store
-- only script-encryption material while private wallet secret fields stay NULL.
CREATE TABLE wallet_secrets (
    -- Reference to the wallet these secrets belong to. Also serves as the
    -- primary key, enforcing one-to-one relationship.
    wallet_id INTEGER PRIMARY KEY,

    -- Params to derive the private master key. NULL for watch-only wallets.
    master_priv_params BLOB,

    -- Encrypted key used to encrypt/decrypt wallet data related to private keys.
    -- NULL for watch-only wallets.
    encrypted_crypto_priv_key BLOB,

    -- Encrypted key used to encrypt/decrypt wallet data related to scripts.
    -- Watch-only wallets may still store this to protect imported scripts.
    encrypted_crypto_script_key BLOB,

    -- Encrypted HD private key of the wallet. NULL for watch-only wallets.
    encrypted_master_hd_priv_key BLOB,

    -- Foreign key constraint to wallet. Using ON DELETE RESTRICT to ensure
    -- that the wallet cannot be deleted if secrets still exist.
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT
);

-- Enforce the watch-only wallet secret invariant at the database boundary.
-- Watch-only wallets may retain script-encryption material for imported
-- scripts, but must never store private key material; keeping these columns
-- NULL prevents an insert or update from silently turning a watch-only wallet
-- into a spend-capable wallet.
CREATE TRIGGER trg_assert_watch_only_wallet_secrets_insert
BEFORE INSERT ON wallet_secrets
FOR EACH ROW
BEGIN
    SELECT raise(ABORT, 'watch-only wallet private secret columns must be null')
    WHERE (
        SELECT w.is_watch_only
        FROM wallets AS w
        WHERE w.id = new.wallet_id
    ) AND (
        new.master_priv_params IS NOT NULL
        OR new.encrypted_crypto_priv_key IS NOT NULL
        OR new.encrypted_master_hd_priv_key IS NOT NULL
    );
END;

CREATE TRIGGER trg_assert_watch_only_wallet_secrets_update
BEFORE UPDATE ON wallet_secrets
FOR EACH ROW
BEGIN
    SELECT raise(ABORT, 'watch-only wallet private secret columns must be null')
    WHERE (
        SELECT w.is_watch_only
        FROM wallets AS w
        WHERE w.id = new.wallet_id
    ) AND (
        new.master_priv_params IS NOT NULL
        OR new.encrypted_crypto_priv_key IS NOT NULL
        OR new.encrypted_master_hd_priv_key IS NOT NULL
    );
END;

-- Wallet Sync States table to store the synchronization state of each wallet.
-- This is kept separate from the wallets table to avoid write amplification on
-- frequently updated sync data. Each wallet has exactly one sync state record.
CREATE TABLE wallet_sync_states (
    -- Reference to the wallet this sync state belongs to. Also serves as the
    -- primary key, enforcing one-to-one relationship.
    wallet_id INTEGER PRIMARY KEY,

    -- Current sync status of the wallet (references blocks table). NULL for wallets
    -- that haven't synced any blocks yet.
    synced_height INTEGER,

    -- Birthday block height of the wallet (references blocks table). NULL if the
    -- wallet has no known birthday block. When set, indicates the block has been
    -- verified.
    birthday_height INTEGER,

    -- User-provided birthday timestamp for wallet rescan. NULL if not set.
    birthday_timestamp DATETIME,

    -- Last updated timestamp stored in UTC without timezone info.
    updated_at DATETIME NOT NULL,

    -- Foreign key constraint to wallet. Using ON DELETE RESTRICT to ensure
    -- that the wallet cannot be deleted if sync state still exists.
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT,

    -- Foreign key constraint to blocks. Using ON DELETE RESTRICT to ensure
    -- that the block cannot be deleted if it is referenced by the sync state.
    FOREIGN KEY (synced_height) REFERENCES blocks (block_height)
    ON DELETE RESTRICT,

    -- Foreign key constraint to blocks. Using ON DELETE RESTRICT to ensure
    -- that the block cannot be deleted if it is referenced by the sync state.
    FOREIGN KEY (birthday_height) REFERENCES blocks (block_height)
    ON DELETE RESTRICT
);
