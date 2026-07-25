-- Active block identities belong to one wallet. The original blocks table is
-- retained as a height registry for foreign keys created by shipped migrations.
CREATE TABLE wallet_blocks (
    wallet_id BIGINT NOT NULL,
    block_height INTEGER NOT NULL CHECK (block_height >= 0),
    header_hash BYTEA NOT NULL CHECK (length(header_hash) = 32),
    block_timestamp BIGINT NOT NULL CHECK (block_timestamp >= 0),
    PRIMARY KEY (wallet_id, block_height),
    UNIQUE (wallet_id, header_hash),
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT
);

-- Existing global identities are valid candidates for every existing wallet.
-- Future writes replace them independently in wallet_blocks.
INSERT INTO wallet_blocks (
    wallet_id, block_height, header_hash, block_timestamp
)
SELECT w.id, b.block_height, b.header_hash, b.block_timestamp
FROM wallets AS w
CROSS JOIN blocks AS b;

ALTER TABLE wallet_sync_states
ADD CONSTRAINT wallet_sync_states_start_wallet_block_fkey
FOREIGN KEY (wallet_id, start_block_height)
REFERENCES wallet_blocks (wallet_id, block_height) ON DELETE RESTRICT;

ALTER TABLE wallet_sync_states
ADD CONSTRAINT wallet_sync_states_synced_wallet_block_fkey
FOREIGN KEY (wallet_id, synced_block_height)
REFERENCES wallet_blocks (wallet_id, block_height) ON DELETE RESTRICT;

ALTER TABLE wallet_sync_states
ADD CONSTRAINT wallet_sync_states_birthday_wallet_block_fkey
FOREIGN KEY (wallet_id, birthday_block_height)
REFERENCES wallet_blocks (wallet_id, block_height) ON DELETE RESTRICT;

ALTER TABLE transactions
ADD CONSTRAINT transactions_wallet_block_fkey
FOREIGN KEY (wallet_id, block_height)
REFERENCES wallet_blocks (wallet_id, block_height) ON DELETE RESTRICT;
