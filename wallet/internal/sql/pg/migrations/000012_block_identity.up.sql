-- Re-key blocks on a surrogate identity so competing same-height blocks can
-- coexist, and make every mined transaction incidence and wallet sync state
-- reference a block id instead of a bare height.
--
-- PostgreSQL alters foreign keys in place, so the transaction, credit, input,
-- and spend tables keep their rows and surrogate ids untouched; only the block
-- reference columns are re-keyed.

-- blocks gains a surrogate primary key. The header hash is globally unique, so
-- two competing blocks at one height coexist as distinct rows.
CREATE SEQUENCE blocks_id_seq;
ALTER TABLE blocks ADD COLUMN id BIGINT;
UPDATE blocks SET id = nextval('blocks_id_seq');
ALTER TABLE blocks ALTER COLUMN id SET NOT NULL;
ALTER TABLE blocks ALTER COLUMN id SET DEFAULT nextval('blocks_id_seq');
ALTER SEQUENCE blocks_id_seq OWNED BY blocks.id;

-- Add the new block reference columns and backfill them by height. Old blocks
-- had a unique height, so each reference resolves to exactly one id.
ALTER TABLE transactions ADD COLUMN block_id BIGINT;
UPDATE transactions AS t
SET block_id = b.id
FROM blocks AS b
WHERE b.block_height = t.block_height;

ALTER TABLE wallet_sync_states ADD COLUMN start_block_id BIGINT;
ALTER TABLE wallet_sync_states ADD COLUMN synced_block_id BIGINT;
ALTER TABLE wallet_sync_states ADD COLUMN birthday_block_id BIGINT;
UPDATE wallet_sync_states AS s
SET start_block_id = b.id
FROM blocks AS b
WHERE b.block_height = s.start_block_height;
UPDATE wallet_sync_states AS s
SET synced_block_id = b.id
FROM blocks AS b
WHERE b.block_height = s.synced_block_height;
UPDATE wallet_sync_states AS s
SET birthday_block_id = b.id
FROM blocks AS b
WHERE b.block_height = s.birthday_block_height;

-- Drop the old height columns. This drops their foreign keys, the transaction
-- block/order check, and every transaction index built on block_height.
ALTER TABLE transactions DROP COLUMN block_height;
ALTER TABLE wallet_sync_states DROP COLUMN start_block_height;
ALTER TABLE wallet_sync_states DROP COLUMN synced_block_height;
ALTER TABLE wallet_sync_states DROP COLUMN birthday_block_height;

-- Re-key blocks: id becomes the primary key; height stays NOT NULL but no longer
-- unique, and gains its own index for range lookups.
ALTER TABLE blocks DROP CONSTRAINT blocks_pkey;
ALTER TABLE blocks ADD CONSTRAINT blocks_pkey PRIMARY KEY (id);
ALTER TABLE blocks ALTER COLUMN block_height SET NOT NULL;
CREATE INDEX idx_blocks_height ON blocks (block_height);

-- Restore the transaction block/order invariant and the block foreign key on
-- the new column.
ALTER TABLE transactions
    ADD CONSTRAINT transactions_block_order_check CHECK (
        (block_id IS NULL AND confirmed_order IS NULL)
        OR (block_id IS NOT NULL AND confirmed_order IS NOT NULL)
    );
ALTER TABLE transactions
    ADD CONSTRAINT transactions_block_id_fkey
    FOREIGN KEY (block_id) REFERENCES blocks (id) ON DELETE RESTRICT;

-- Sync state keeps a mandatory start and synced block and an optional birthday
-- block.
ALTER TABLE wallet_sync_states ALTER COLUMN start_block_id SET NOT NULL;
ALTER TABLE wallet_sync_states ALTER COLUMN synced_block_id SET NOT NULL;
ALTER TABLE wallet_sync_states
    ADD CONSTRAINT wallet_sync_states_start_block_id_fkey
    FOREIGN KEY (start_block_id) REFERENCES blocks (id) ON DELETE RESTRICT;
ALTER TABLE wallet_sync_states
    ADD CONSTRAINT wallet_sync_states_synced_block_id_fkey
    FOREIGN KEY (synced_block_id) REFERENCES blocks (id) ON DELETE RESTRICT;
ALTER TABLE wallet_sync_states
    ADD CONSTRAINT wallet_sync_states_birthday_block_id_fkey
    FOREIGN KEY (birthday_block_id) REFERENCES blocks (id) ON DELETE RESTRICT;

-- Recreate the transaction indexes on the block id. Only one mined incidence per
-- block and one unmined incidence per wallet are allowed.
CREATE UNIQUE INDEX uidx_transactions_unmined_hash
ON transactions (wallet_id, tx_hash)
WHERE block_id IS NULL;

CREATE UNIQUE INDEX uidx_transactions_mined_incidence
ON transactions (wallet_id, tx_hash, block_id)
WHERE block_id IS NOT NULL;

CREATE UNIQUE INDEX uidx_transactions_block_order
ON transactions (wallet_id, block_id, confirmed_order)
WHERE block_id IS NOT NULL;

CREATE INDEX idx_transactions_hash
ON transactions (wallet_id, tx_hash, block_id);

CREATE INDEX idx_transactions_block
ON transactions (wallet_id, block_id, confirmed_order);
