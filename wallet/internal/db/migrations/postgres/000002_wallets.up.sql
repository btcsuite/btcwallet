-- Wallet metadata and related state tables.
--
-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.
CREATE TABLE wallets (
    -- DB ID of the wallet, primary key. Only used for DB level relations.
    id BIGSERIAL PRIMARY KEY,

    -- Human friendly name for the wallet.
    name TEXT NOT NULL,

    -- Defines if the wallet was imported, all its accounts would also be imported.
    is_imported BOOLEAN NOT NULL,

    -- Version of the wallet manager that created this wallet.
    manager_version INTEGER NOT NULL,

    -- Defines if the wallet is a watch-only wallet.
    is_watch_only BOOLEAN NOT NULL,

    -- Params to derive the public master key.
    master_pub_params BYTEA NOT NULL,

    -- Encrypted key used to encrypt/decrypt wallet data related to public keys.
    encrypted_crypto_pub_key BYTEA NOT NULL,

    -- Encrypted HD public key of the wallet. NULL for certain wallet types
    -- that don't store extended public keys.
    encrypted_master_hd_pub_key BYTEA
);

-- Unique index to prevent duplicate wallet names.
CREATE UNIQUE INDEX uidx_wallets_name ON wallets (name);

-- Wallet Secrets table to store rarely accessed, highly sensitive encrypted
-- material with a strict one-to-one relationship with the wallets table.
-- Separated from the main wallets table for security and access pattern isolation.
-- Watch-only wallets may have no corresponding row in this table or have all
-- private key fields with no data.
CREATE TABLE wallet_secrets (
    -- Reference to the wallet these secrets belong to. Acts as the primary key
    -- via the unique index below, enforcing one-to-one relationship.
    wallet_id BIGINT NOT NULL,

    -- Params to derive the private master key. NULL for watch-only wallets.
    master_priv_params BYTEA,

    -- Encrypted key used to encrypt/decrypt wallet data related to private keys.
    -- NULL for watch-only wallets.
    encrypted_crypto_priv_key BYTEA,

    -- Encrypted key used to encrypt/decrypt wallet data related to scripts.
    -- NULL for watch-only wallets.
    encrypted_crypto_script_key BYTEA,

    -- Encrypted HD private key of the wallet. NULL for watch-only wallets.
    encrypted_master_hd_priv_key BYTEA,

    -- Foreign key constraint to wallet. Using ON DELETE RESTRICT to ensure
    -- that the wallet cannot be deleted if secrets still exist.
    FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE RESTRICT
);

-- Enforces one-to-one relationship: each wallet has at most one secrets record.
-- Also serves as the effective primary key for this table.
CREATE UNIQUE INDEX uidx_wallet_secrets_wallet ON wallet_secrets (wallet_id);

-- Wallet Sync States table to store the synchronization state of each wallet.
-- This is kept separate from the wallets table to avoid write amplification on
-- frequently updated sync data. Each wallet has exactly one sync state record.
CREATE TABLE wallet_sync_states (
    -- Reference to the wallet this sync state belongs to. Acts as the primary key
    -- via the unique index below, enforcing one-to-one relationship.
    wallet_id BIGINT NOT NULL,

    -- Current sync status of the wallet (references blocks table). NULL for wallets
    -- that haven't synced any blocks yet.
    synced_height INTEGER,

    -- Birthday block height of the wallet (references blocks table). NULL if the
    -- wallet has no known birthday block. When set, indicates the block has been
    -- verified.
    birthday_height INTEGER,

    -- User-provided birthday timestamp for wallet rescan. NULL if not set.
    birthday TIMESTAMP,

    -- Last updated timestamp stored in UTC without timezone info.
    updated_at TIMESTAMP NOT NULL,

    -- Foreign key constraint to wallet. Using ON DELETE RESTRICT to ensure
    -- that the wallet cannot be deleted if sync state still exists.
    FOREIGN KEY (wallet_id) REFERENCES wallets(id) ON DELETE RESTRICT,

    -- Foreign key constraint to blocks. Using ON DELETE RESTRICT to ensure
    -- that the block cannot be deleted if it is referenced by the sync state.
    FOREIGN KEY (synced_height) REFERENCES blocks(block_height)
        ON DELETE RESTRICT,

    -- Foreign key constraint to blocks. Using ON DELETE RESTRICT to ensure
    -- that the block cannot be deleted if it is referenced by the sync state.
    FOREIGN KEY (birthday_height) REFERENCES blocks(block_height)
        ON DELETE RESTRICT
);

-- Enforces one-to-one relationship: each wallet has exactly one sync state record.
-- Also serves as the effective primary key for this table.
CREATE UNIQUE INDEX uidx_wallet_sync_states_wallet
    ON wallet_sync_states (wallet_id);
