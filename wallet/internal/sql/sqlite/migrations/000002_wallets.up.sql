-- The wallets table preserves the legacy waddrmgr encryption hierarchy.
CREATE TABLE wallets (
    id INTEGER PRIMARY KEY,
    wallet_name TEXT NOT NULL UNIQUE,
    manager_version INTEGER NOT NULL
        CHECK (manager_version BETWEEN 0 AND 4294967295),
    manager_created_at INTEGER NOT NULL CHECK (manager_created_at >= 0),
    is_watch_only BOOLEAN NOT NULL CHECK (is_watch_only IN (FALSE, TRUE)),
    master_pub_params BLOB NOT NULL,
    master_priv_params BLOB,
    encrypted_crypto_pub_key BLOB NOT NULL,
    encrypted_crypto_priv_key BLOB,
    encrypted_crypto_script_key BLOB,
    encrypted_master_hd_pub_key BLOB,
    encrypted_master_hd_priv_key BLOB
);

-- The wallet sync state mirrors the block stamps and birthday metadata stored
-- by the legacy address manager.
CREATE TABLE wallet_sync_states (
    wallet_id INTEGER PRIMARY KEY,
    start_block_height INTEGER NOT NULL,
    synced_block_height INTEGER NOT NULL,
    birthday_timestamp INTEGER NOT NULL CHECK (birthday_timestamp >= 0),
    birthday_block_height INTEGER,
    birthday_block_verified BOOLEAN NOT NULL DEFAULT FALSE
        CHECK (birthday_block_verified IN (FALSE, TRUE)),
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT,
    FOREIGN KEY (start_block_height) REFERENCES blocks (block_height)
        ON DELETE RESTRICT,
    FOREIGN KEY (synced_block_height) REFERENCES blocks (block_height)
        ON DELETE RESTRICT,
    FOREIGN KEY (birthday_block_height) REFERENCES blocks (block_height)
        ON DELETE RESTRICT,
    CHECK (
        birthday_block_verified = FALSE
        OR birthday_block_height IS NOT NULL
    )
);
