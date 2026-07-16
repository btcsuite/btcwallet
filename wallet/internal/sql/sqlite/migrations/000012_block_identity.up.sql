-- Re-key blocks on a surrogate identity so competing same-height blocks can
-- coexist, and make every mined transaction incidence and wallet sync state
-- reference a block id instead of a bare height.
--
-- SQLite cannot alter a column's foreign key in place, and the blocks and
-- transactions tables are foreign-key parents of the sync-state, credit, input,
-- and spend tables. The golang-migrate SQLite driver wraps this file in a
-- transaction, where PRAGMA foreign_keys is a no-op, so the classic
-- foreign_keys=OFF rebuild is unavailable. Instead the whole affected cluster
-- is rebuilt with defer_foreign_keys: renaming a parent retargets its children
-- to the *_old copies, so the children are recreated against the new parents
-- and the old copies are dropped bottom-up. Deferring foreign keys lets the
-- intermediate cross-table state exist until the final COMMIT validates it.
--
-- Renaming a table keeps its explicit indexes under the same names, so every
-- CREATE INDEX is deferred until after the *_old tables are dropped to avoid a
-- name collision.
PRAGMA defer_foreign_keys = ON;

-- Move every table in the foreign-key cluster out of the way. transaction_labels
-- references only wallets, so it is left untouched.
ALTER TABLE blocks RENAME TO blocks_old;
ALTER TABLE wallet_sync_states RENAME TO wallet_sync_states_old;
ALTER TABLE transactions RENAME TO transactions_old;
ALTER TABLE transaction_inputs RENAME TO transaction_inputs_old;
ALTER TABLE credits RENAME TO credits_old;
ALTER TABLE active_credit_incidences RENAME TO active_credit_incidences_old;
ALTER TABLE credit_spends RENAME TO credit_spends_old;

-- blocks gains a surrogate primary key. The header hash is globally unique, so
-- two competing blocks at one height coexist as distinct rows.
CREATE TABLE blocks (
    id INTEGER PRIMARY KEY,
    block_height INTEGER NOT NULL CHECK (block_height >= 0),
    header_hash BLOB NOT NULL UNIQUE CHECK (length(header_hash) = 32),
    block_timestamp INTEGER NOT NULL CHECK (block_timestamp >= 0)
);

INSERT INTO blocks (block_height, header_hash, block_timestamp)
SELECT block_height, header_hash, block_timestamp FROM blocks_old;

-- Map every old height to its new surrogate id. Old blocks had a unique height,
-- so this mapping is one-to-one.
CREATE TABLE block_height_map (
    old_height INTEGER PRIMARY KEY,
    block_id INTEGER NOT NULL
);

INSERT INTO block_height_map (old_height, block_id)
SELECT block_height, id FROM blocks;

-- transactions now references a block id. Surrogate ids are preserved so the
-- credit, input, and spend rows copied below keep referring to the same rows.
CREATE TABLE transactions (
    id INTEGER PRIMARY KEY,
    wallet_id INTEGER NOT NULL,
    tx_hash BLOB NOT NULL CHECK (length(tx_hash) = 32),
    raw_tx BLOB NOT NULL,
    received_unix INTEGER NOT NULL,
    block_id INTEGER,
    confirmed_order INTEGER CHECK (
        confirmed_order BETWEEN 0 AND 4294967295
    ),
    is_coinbase BOOLEAN NOT NULL CHECK (is_coinbase IN (FALSE, TRUE)),
    UNIQUE (wallet_id, id),
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT,
    FOREIGN KEY (block_id) REFERENCES blocks (id) ON DELETE RESTRICT,
    CHECK (
        (block_id IS NULL AND confirmed_order IS NULL)
        OR (block_id IS NOT NULL AND confirmed_order IS NOT NULL)
    )
);

INSERT INTO transactions (
    id, wallet_id, tx_hash, raw_tx, received_unix, block_id, confirmed_order,
    is_coinbase
)
SELECT
    t.id, t.wallet_id, t.tx_hash, t.raw_tx, t.received_unix, m.block_id,
    t.confirmed_order, t.is_coinbase
FROM transactions_old AS t
LEFT JOIN block_height_map AS m ON m.old_height = t.block_height;

-- The remaining cluster tables keep their schema unchanged; they are recreated
-- only so their foreign keys bind to the new parents rather than the *_old
-- copies.
CREATE TABLE transaction_inputs (
    spending_tx_id INTEGER NOT NULL,
    input_index INTEGER NOT NULL
        CHECK (input_index BETWEEN 0 AND 4294967295),
    prev_tx_hash BLOB NOT NULL CHECK (length(prev_tx_hash) = 32),
    prev_output_index INTEGER NOT NULL
        CHECK (prev_output_index BETWEEN 0 AND 4294967295),
    PRIMARY KEY (spending_tx_id, input_index),
    FOREIGN KEY (spending_tx_id) REFERENCES transactions (id)
        ON DELETE CASCADE
);

INSERT INTO transaction_inputs (
    spending_tx_id, input_index, prev_tx_hash, prev_output_index
)
SELECT spending_tx_id, input_index, prev_tx_hash, prev_output_index
FROM transaction_inputs_old;

CREATE TABLE credits (
    id INTEGER PRIMARY KEY,
    wallet_id INTEGER NOT NULL,
    transaction_id INTEGER NOT NULL,
    output_index INTEGER NOT NULL
        CHECK (output_index BETWEEN 0 AND 4294967295),
    amount INTEGER NOT NULL CHECK (amount >= 0),
    pk_script BLOB NOT NULL,
    is_change BOOLEAN NOT NULL CHECK (is_change IN (FALSE, TRUE)),
    address_scope_id INTEGER,
    address_id BLOB CHECK (address_id IS NULL OR length(address_id) = 32),
    UNIQUE (transaction_id, output_index),
    UNIQUE (wallet_id, id),
    FOREIGN KEY (wallet_id, transaction_id)
        REFERENCES transactions (wallet_id, id) ON DELETE CASCADE,
    FOREIGN KEY (wallet_id, address_scope_id, address_id)
        REFERENCES addresses (wallet_id, scope_id, address_hash)
        ON DELETE RESTRICT,
    CHECK (
        (address_scope_id IS NULL AND address_id IS NULL)
        OR (address_scope_id IS NOT NULL AND address_id IS NOT NULL)
    )
);

INSERT INTO credits (
    id, wallet_id, transaction_id, output_index, amount, pk_script, is_change,
    address_scope_id, address_id
)
SELECT
    id, wallet_id, transaction_id, output_index, amount, pk_script, is_change,
    address_scope_id, address_id
FROM credits_old;

CREATE TABLE active_credit_incidences (
    wallet_id INTEGER NOT NULL,
    tx_hash BLOB NOT NULL CHECK (length(tx_hash) = 32),
    output_index INTEGER NOT NULL
        CHECK (output_index BETWEEN 0 AND 4294967295),
    credit_id INTEGER NOT NULL UNIQUE,
    PRIMARY KEY (wallet_id, tx_hash, output_index),
    FOREIGN KEY (wallet_id, credit_id)
        REFERENCES credits (wallet_id, id) ON DELETE CASCADE
);

INSERT INTO active_credit_incidences (
    wallet_id, tx_hash, output_index, credit_id
)
SELECT wallet_id, tx_hash, output_index, credit_id
FROM active_credit_incidences_old;

CREATE TABLE credit_spends (
    wallet_id INTEGER NOT NULL,
    credit_id INTEGER PRIMARY KEY,
    spending_tx_id INTEGER NOT NULL,
    input_index INTEGER NOT NULL
        CHECK (input_index BETWEEN 0 AND 4294967295),
    UNIQUE (spending_tx_id, input_index),
    FOREIGN KEY (wallet_id, credit_id)
        REFERENCES credits (wallet_id, id) ON DELETE CASCADE,
    FOREIGN KEY (wallet_id, spending_tx_id)
        REFERENCES transactions (wallet_id, id) ON DELETE CASCADE,
    FOREIGN KEY (spending_tx_id, input_index)
        REFERENCES transaction_inputs (spending_tx_id, input_index)
        ON DELETE CASCADE
);

INSERT INTO credit_spends (
    wallet_id, credit_id, spending_tx_id, input_index
)
SELECT wallet_id, credit_id, spending_tx_id, input_index
FROM credit_spends_old;

-- Wallet sync state references block ids. The birthday block stays nullable and
-- its verification bit stays independent (migration 10).
CREATE TABLE wallet_sync_states (
    wallet_id INTEGER PRIMARY KEY,
    start_block_id INTEGER NOT NULL,
    synced_block_id INTEGER NOT NULL,
    birthday_timestamp INTEGER NOT NULL CHECK (birthday_timestamp >= 0),
    birthday_block_id INTEGER,
    birthday_block_verified BOOLEAN NOT NULL DEFAULT FALSE
        CHECK (birthday_block_verified IN (FALSE, TRUE)),
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT,
    FOREIGN KEY (start_block_id) REFERENCES blocks (id) ON DELETE RESTRICT,
    FOREIGN KEY (synced_block_id) REFERENCES blocks (id) ON DELETE RESTRICT,
    FOREIGN KEY (birthday_block_id) REFERENCES blocks (id) ON DELETE RESTRICT
);

INSERT INTO wallet_sync_states (
    wallet_id, start_block_id, synced_block_id, birthday_timestamp,
    birthday_block_id, birthday_block_verified
)
SELECT
    s.wallet_id, start_map.block_id, synced_map.block_id, s.birthday_timestamp,
    birthday_map.block_id, s.birthday_block_verified
FROM wallet_sync_states_old AS s
INNER JOIN block_height_map AS start_map
    ON start_map.old_height = s.start_block_height
INNER JOIN block_height_map AS synced_map
    ON synced_map.old_height = s.synced_block_height
LEFT JOIN block_height_map AS birthday_map
    ON birthday_map.old_height = s.birthday_block_height;

-- Verify the rebuild before dropping the source tables. A violated invariant
-- fails the CHECK on the insert and aborts the whole migration.
CREATE TEMP TABLE _assert_block_identity (ok INTEGER NOT NULL CHECK (ok = 1));

INSERT INTO _assert_block_identity (ok)
SELECT CASE WHEN
    (SELECT count(*) FROM blocks) = (SELECT count(*) FROM blocks_old)
    AND (SELECT count(*) FROM transactions)
        = (SELECT count(*) FROM transactions_old)
    AND (SELECT count(*) FROM transaction_inputs)
        = (SELECT count(*) FROM transaction_inputs_old)
    AND (SELECT count(*) FROM credits) = (SELECT count(*) FROM credits_old)
    AND (SELECT count(*) FROM active_credit_incidences)
        = (SELECT count(*) FROM active_credit_incidences_old)
    AND (SELECT count(*) FROM credit_spends)
        = (SELECT count(*) FROM credit_spends_old)
    AND (SELECT count(*) FROM wallet_sync_states)
        = (SELECT count(*) FROM wallet_sync_states_old)
    -- Every transaction that was mined keeps a non-null block id.
    AND NOT EXISTS (
        SELECT 1 FROM transactions_old AS o
        INNER JOIN transactions AS n ON n.id = o.id
        WHERE o.block_height IS NOT NULL AND n.block_id IS NULL
    )
    -- Every sync state keeps its start and synced block ids.
    AND NOT EXISTS (
        SELECT 1 FROM wallet_sync_states
        WHERE start_block_id IS NULL OR synced_block_id IS NULL
    )
THEN 1 ELSE 0 END;

DROP TABLE _assert_block_identity;

-- Drop the source tables child-first so a parent drop never cascades into live
-- rows, then drop the height mapping. Dropping a table also drops its indexes,
-- freeing the names reused below.
DROP TABLE credit_spends_old;
DROP TABLE active_credit_incidences_old;
DROP TABLE transaction_inputs_old;
DROP TABLE credits_old;
DROP TABLE transactions_old;
DROP TABLE wallet_sync_states_old;
DROP TABLE blocks_old;
DROP TABLE block_height_map;

-- Recreate every explicit index on the new tables.
CREATE INDEX idx_blocks_height ON blocks (block_height);

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

CREATE INDEX idx_transaction_inputs_prevout
ON transaction_inputs (prev_tx_hash, prev_output_index, spending_tx_id);

CREATE INDEX idx_credits_wallet_transaction
ON credits (wallet_id, transaction_id, output_index);

CREATE INDEX idx_credits_address
ON credits (wallet_id, address_scope_id, address_id);
