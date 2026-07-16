-- Reverse the surrogate block identity, restoring height as the blocks primary
-- key and re-keying transactions and sync state on height.
--
-- This is only possible while at most one block exists per height. A fork of
-- competing same-height blocks cannot be represented by a height primary key,
-- so the rollback refuses rather than silently discarding one side of the fork.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM blocks GROUP BY block_height HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION
            'irreversible migration: competing same-height blocks exist';
    END IF;
END $$;

-- Restore the height columns and backfill them from the surrogate ids while the
-- id column still exists.
ALTER TABLE transactions ADD COLUMN block_height INTEGER;
UPDATE transactions AS t
SET block_height = b.block_height
FROM blocks AS b
WHERE b.id = t.block_id;

ALTER TABLE wallet_sync_states ADD COLUMN start_block_height INTEGER;
ALTER TABLE wallet_sync_states ADD COLUMN synced_block_height INTEGER;
ALTER TABLE wallet_sync_states ADD COLUMN birthday_block_height INTEGER;
UPDATE wallet_sync_states AS s
SET start_block_height = b.block_height
FROM blocks AS b
WHERE b.id = s.start_block_id;
UPDATE wallet_sync_states AS s
SET synced_block_height = b.block_height
FROM blocks AS b
WHERE b.id = s.synced_block_id;
UPDATE wallet_sync_states AS s
SET birthday_block_height = b.block_height
FROM blocks AS b
WHERE b.id = s.birthday_block_id;

-- Drop the id-based indexes and columns. Dropping a column drops its foreign
-- key and any index or check built on it.
DROP INDEX uidx_transactions_unmined_hash;
DROP INDEX uidx_transactions_mined_incidence;
DROP INDEX uidx_transactions_block_order;
DROP INDEX idx_transactions_hash;
DROP INDEX idx_transactions_block;
ALTER TABLE transactions DROP COLUMN block_id;
ALTER TABLE wallet_sync_states DROP COLUMN start_block_id;
ALTER TABLE wallet_sync_states DROP COLUMN synced_block_id;
ALTER TABLE wallet_sync_states DROP COLUMN birthday_block_id;

-- Restore height as the blocks primary key. Dropping the id column drops the
-- sequence it owns.
DROP INDEX idx_blocks_height;
ALTER TABLE blocks DROP CONSTRAINT blocks_pkey;
ALTER TABLE blocks DROP COLUMN id;
ALTER TABLE blocks ADD CONSTRAINT blocks_pkey PRIMARY KEY (block_height);

-- Restore the transaction height column invariants, foreign key, and indexes.
ALTER TABLE transactions
    ADD CONSTRAINT transactions_block_order_check CHECK (
        (block_height IS NULL AND confirmed_order IS NULL)
        OR (block_height IS NOT NULL AND confirmed_order IS NOT NULL)
    );
ALTER TABLE transactions
    ADD CONSTRAINT transactions_block_height_fkey
    FOREIGN KEY (block_height) REFERENCES blocks (block_height)
    ON DELETE RESTRICT;

CREATE UNIQUE INDEX uidx_transactions_unmined_hash
ON transactions (wallet_id, tx_hash)
WHERE block_height IS NULL;

CREATE UNIQUE INDEX uidx_transactions_mined_incidence
ON transactions (wallet_id, tx_hash, block_height)
WHERE block_height IS NOT NULL;

CREATE UNIQUE INDEX uidx_transactions_block_order
ON transactions (wallet_id, block_height, confirmed_order)
WHERE block_height IS NOT NULL;

CREATE INDEX idx_transactions_hash
ON transactions (wallet_id, tx_hash, block_height);

CREATE INDEX idx_transactions_block
ON transactions (wallet_id, block_height, confirmed_order);

-- Restore the sync-state height columns, invariants, and foreign keys.
ALTER TABLE wallet_sync_states ALTER COLUMN start_block_height SET NOT NULL;
ALTER TABLE wallet_sync_states ALTER COLUMN synced_block_height SET NOT NULL;
ALTER TABLE wallet_sync_states
    ADD CONSTRAINT wallet_sync_states_start_block_height_fkey
    FOREIGN KEY (start_block_height) REFERENCES blocks (block_height)
    ON DELETE RESTRICT;
ALTER TABLE wallet_sync_states
    ADD CONSTRAINT wallet_sync_states_synced_block_height_fkey
    FOREIGN KEY (synced_block_height) REFERENCES blocks (block_height)
    ON DELETE RESTRICT;
ALTER TABLE wallet_sync_states
    ADD CONSTRAINT wallet_sync_states_birthday_block_height_fkey
    FOREIGN KEY (birthday_block_height) REFERENCES blocks (block_height)
    ON DELETE RESTRICT;
