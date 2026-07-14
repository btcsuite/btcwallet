-- The legacy address manager retains the verification bit when the birthday
-- block is removed. Rebuild the table without coupling those two fields.
CREATE TABLE wallet_sync_states_new (
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
        ON DELETE RESTRICT
);

INSERT INTO wallet_sync_states_new (
    wallet_id,
    start_block_height,
    synced_block_height,
    birthday_timestamp,
    birthday_block_height,
    birthday_block_verified
)
SELECT
    wallet_id,
    start_block_height,
    synced_block_height,
    birthday_timestamp,
    birthday_block_height,
    birthday_block_verified
FROM wallet_sync_states;

DROP TABLE wallet_sync_states;
ALTER TABLE wallet_sync_states_new RENAME TO wallet_sync_states;
