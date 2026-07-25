-- Active block identities belong to one wallet. The original blocks table is
-- retained as a height registry for foreign keys created by shipped migrations.
CREATE TABLE wallet_blocks (
    wallet_id INTEGER NOT NULL,
    block_height INTEGER NOT NULL CHECK (block_height >= 0),
    header_hash BLOB NOT NULL CHECK (length(header_hash) = 32),
    block_timestamp INTEGER NOT NULL CHECK (block_timestamp >= 0),
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

-- SQLite cannot add composite foreign keys without rebuilding shipped tables.
-- These triggers enforce the wallet-scoped relationships without changing the
-- semantics of prior migrations.
CREATE TRIGGER wallet_sync_states_insert_blocks
BEFORE INSERT ON wallet_sync_states
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM wallet_blocks
        WHERE wallet_id = NEW.wallet_id
          AND block_height = NEW.start_block_height
    ) THEN RAISE(ABORT, 'wallet start block not found') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM wallet_blocks
        WHERE wallet_id = NEW.wallet_id
          AND block_height = NEW.synced_block_height
    ) THEN RAISE(ABORT, 'wallet synced block not found') END;
    SELECT CASE WHEN NEW.birthday_block_height IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM wallet_blocks
        WHERE wallet_id = NEW.wallet_id
          AND block_height = NEW.birthday_block_height
    ) THEN RAISE(ABORT, 'wallet birthday block not found') END;
END;

CREATE TRIGGER wallet_sync_states_update_blocks
BEFORE UPDATE OF wallet_id, start_block_height, synced_block_height,
    birthday_block_height ON wallet_sync_states
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM wallet_blocks
        WHERE wallet_id = NEW.wallet_id
          AND block_height = NEW.start_block_height
    ) THEN RAISE(ABORT, 'wallet start block not found') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM wallet_blocks
        WHERE wallet_id = NEW.wallet_id
          AND block_height = NEW.synced_block_height
    ) THEN RAISE(ABORT, 'wallet synced block not found') END;
    SELECT CASE WHEN NEW.birthday_block_height IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM wallet_blocks
        WHERE wallet_id = NEW.wallet_id
          AND block_height = NEW.birthday_block_height
    ) THEN RAISE(ABORT, 'wallet birthday block not found') END;
END;

CREATE TRIGGER transactions_insert_block
BEFORE INSERT ON transactions
WHEN NEW.block_height IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM wallet_blocks
        WHERE wallet_id = NEW.wallet_id
          AND block_height = NEW.block_height
    ) THEN RAISE(ABORT, 'transaction block not found') END;
END;

CREATE TRIGGER transactions_update_block
BEFORE UPDATE OF wallet_id, block_height ON transactions
WHEN NEW.block_height IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM wallet_blocks
        WHERE wallet_id = NEW.wallet_id
          AND block_height = NEW.block_height
    ) THEN RAISE(ABORT, 'transaction block not found') END;
END;

CREATE TRIGGER wallet_blocks_delete_restrict
BEFORE DELETE ON wallet_blocks
WHEN EXISTS (
    SELECT 1 FROM wallet_sync_states
    WHERE wallet_id = OLD.wallet_id
      AND (
          start_block_height = OLD.block_height
          OR synced_block_height = OLD.block_height
          OR birthday_block_height = OLD.block_height
      )
    UNION ALL
    SELECT 1 FROM transactions
    WHERE wallet_id = OLD.wallet_id
      AND block_height = OLD.block_height
)
BEGIN
    SELECT RAISE(ABORT, 'wallet block is still referenced');
END;
