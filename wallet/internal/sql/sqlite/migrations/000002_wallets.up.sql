-- Wallet metadata and related state tables.
--
-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.
-- Wallet Secrets table to store rarely accessed, highly sensitive encrypted
-- material with a strict one-to-one relationship with the wallets table.
-- Separated from the main wallets table for security and access pattern isolation.
-- Every wallet has a corresponding row in this table. Watch-only wallets still
-- require script-encryption material while private wallet secret fields stay NULL.
CREATE TABLE wallet_secrets (
    -- Reference to the wallet these secrets belong to. Also serves as the
    -- primary key, enforcing one-to-one relationship.
    wallet_id INTEGER PRIMARY KEY,

    -- Params to derive the private master key. Required for every wallet,
    -- including watch-only wallets, because these derive the key that protects
    -- the script crypto key.
    master_priv_params BLOB NOT NULL,

    -- Encrypted key used to encrypt/decrypt wallet data related to private keys.
    -- NULL for watch-only wallets.
    encrypted_crypto_priv_key BLOB,

    -- Encrypted key used to encrypt/decrypt wallet data related to scripts.
    -- NOT NULL and required for every wallet, including watch-only wallets, to
    -- protect script and imported-script material.
    encrypted_crypto_script_key BLOB NOT NULL,

    -- Encrypted HD private key of the wallet. NULL for watch-only wallets.
    encrypted_master_hd_priv_key BLOB,

    -- Foreign key constraint to wallet. Using ON DELETE RESTRICT to ensure
    -- that the wallet cannot be deleted if secrets still exist.
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT,

    -- NOT NULL still allows zero-length BLOB values, so these CHECKs keep the
    -- required-secret blobs non-empty at the DB boundary.
    CHECK (length(master_priv_params) > 0),
    CHECK (length(encrypted_crypto_script_key) > 0)
);

-- Enforce wallet-mode secret invariants at the database boundary. Watch-only
-- wallets require script-encryption material for imported scripts, but must
-- never store private key material. Spendable wallets must store the encrypted
-- private crypto key and encrypted master HD private key they need to unlock.
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
        new.encrypted_crypto_priv_key IS NOT NULL
        OR new.encrypted_master_hd_priv_key IS NOT NULL
    );

    SELECT
        raise(
            ABORT, 'spendable wallet private secret columns must be non-empty'
        )
    WHERE NOT (
        SELECT w.is_watch_only
        FROM wallets AS w
        WHERE w.id = new.wallet_id
    ) AND (
        new.encrypted_crypto_priv_key IS NULL
        OR length(new.encrypted_crypto_priv_key) = 0
        OR new.encrypted_master_hd_priv_key IS NULL
        OR length(new.encrypted_master_hd_priv_key) = 0
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
        new.encrypted_crypto_priv_key IS NOT NULL
        OR new.encrypted_master_hd_priv_key IS NOT NULL
    );

    SELECT
        raise(
            ABORT, 'spendable wallet private secret columns must be non-empty'
        )
    WHERE NOT (
        SELECT w.is_watch_only
        FROM wallets AS w
        WHERE w.id = new.wallet_id
    ) AND (
        new.encrypted_crypto_priv_key IS NULL
        OR length(new.encrypted_crypto_priv_key) = 0
        OR new.encrypted_master_hd_priv_key IS NULL
        OR length(new.encrypted_master_hd_priv_key) = 0
    );
END;

-- Wallet Sync States table to store the synchronization state of each wallet.
-- This is kept separate from the wallets table to avoid write amplification on
-- frequently updated sync data. Each wallet has exactly one sync state record.
CREATE TABLE wallet_sync_states (
    -- Reference to the wallet this sync state belongs to. Also serves as the
    -- primary key, enforcing one-to-one relationship.
    wallet_id INTEGER PRIMARY KEY,

    -- Current sync status of the wallet (references wallet_blocks table). NULL for wallets
    -- that haven't synced any blocks yet.
    synced_height INTEGER,

    -- Birthday block height of the wallet (references wallet_blocks table). NULL if the
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
    FOREIGN KEY (wallet_id, synced_height)
    REFERENCES wallet_blocks (wallet_id, block_height)
    ON DELETE RESTRICT,

    -- Foreign key constraint to blocks. Using ON DELETE RESTRICT to ensure
    -- that the block cannot be deleted if it is referenced by the sync state.
    FOREIGN KEY (wallet_id, birthday_height)
    REFERENCES wallet_blocks (wallet_id, block_height)
    ON DELETE RESTRICT
);
