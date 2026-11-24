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
    wallet_id BIGINT PRIMARY KEY,

    -- Params to derive the private master key. Required for every wallet,
    -- including watch-only wallets, because these derive the key that protects
    -- the script crypto key.
    master_priv_params BYTEA NOT NULL,

    -- Encrypted key used to encrypt/decrypt wallet data related to private keys.
    -- NULL for watch-only wallets.
    encrypted_crypto_priv_key BYTEA,

    -- Encrypted key used to encrypt/decrypt wallet data related to scripts.
    -- NOT NULL and required for every wallet, including watch-only wallets, to
    -- protect script and imported-script material.
    encrypted_crypto_script_key BYTEA NOT NULL,

    -- Encrypted HD private key of the wallet. NULL for watch-only wallets.
    encrypted_master_hd_priv_key BYTEA,

    -- Foreign key constraint to wallet. Using ON DELETE RESTRICT to ensure
    -- that the wallet cannot be deleted if secrets still exist.
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT,

    -- NOT NULL still allows zero-length bytea values, so these CHECKs keep the
    -- required-secret blobs non-empty at the DB boundary.
    CHECK (length(master_priv_params) > 0),
    CHECK (length(encrypted_crypto_script_key) > 0)
);

-- Enforce wallet-mode secret invariants at the database boundary. Watch-only
-- wallets require script-encryption material for imported scripts, but must
-- never store private key material. Spendable wallets must store the encrypted
-- private crypto key and encrypted master HD private key they need to unlock.
CREATE FUNCTION assert_watch_only_wallet_secrets() RETURNS TRIGGER AS $$
DECLARE
    wallet_is_watch_only BOOLEAN;
BEGIN
    SELECT w.is_watch_only INTO wallet_is_watch_only
    FROM wallets AS w
    WHERE w.id = NEW.wallet_id;

    IF wallet_is_watch_only AND (
        NEW.encrypted_crypto_priv_key IS NOT NULL
        OR NEW.encrypted_master_hd_priv_key IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'watch-only wallet private secret columns must be null'
            USING ERRCODE = '23514'; -- check_violation
    END IF;

    IF NOT wallet_is_watch_only AND (
        NEW.encrypted_crypto_priv_key IS NULL
        OR length(NEW.encrypted_crypto_priv_key) = 0
        OR NEW.encrypted_master_hd_priv_key IS NULL
        OR length(NEW.encrypted_master_hd_priv_key) = 0
    ) THEN
        RAISE EXCEPTION 'spendable wallet private secret columns must be non-empty'
            USING ERRCODE = '23514'; -- check_violation
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_assert_watch_only_wallet_secrets_insert
BEFORE INSERT ON wallet_secrets
FOR EACH ROW
EXECUTE FUNCTION assert_watch_only_wallet_secrets();

CREATE TRIGGER trg_assert_watch_only_wallet_secrets_update
BEFORE UPDATE ON wallet_secrets
FOR EACH ROW
EXECUTE FUNCTION assert_watch_only_wallet_secrets();

-- Wallet Sync States table to store the synchronization state of each wallet.
-- This is kept separate from the wallets table to avoid write amplification on
-- frequently updated sync data. Each wallet has exactly one sync state record.
CREATE TABLE wallet_sync_states (
    -- Reference to the wallet this sync state belongs to. Also serves as the
    -- primary key, enforcing one-to-one relationship.
    wallet_id BIGINT PRIMARY KEY,

    -- Current sync status of the wallet (references wallet_blocks table). NULL for wallets
    -- that haven't synced any blocks yet.
    synced_height INTEGER,

    -- Birthday block height of the wallet (references wallet_blocks table). NULL if the
    -- wallet has no known birthday block. When set, indicates the block has been
    -- verified.
    birthday_height INTEGER,

    -- User-provided birthday timestamp for wallet rescan. NULL if not set.
    birthday_timestamp TIMESTAMP,

    -- Last updated timestamp stored in UTC without timezone info.
    updated_at TIMESTAMP NOT NULL,

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
