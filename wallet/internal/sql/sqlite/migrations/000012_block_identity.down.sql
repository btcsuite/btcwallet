-- Reverse the surrogate block identity, restoring height as the blocks primary
-- key and re-keying transactions and sync state on height.
--
-- This is only possible while at most one block exists per height. A fork of
-- competing same-height blocks cannot be represented by a height primary key,
-- so the rollback refuses rather than silently discarding one side of the fork.
-- The assertion below aborts the migration in that case.
--
-- As in the up migration, renaming a table keeps its explicit indexes under the
-- same names, so every CREATE INDEX is deferred until after the *_old tables are
-- dropped.
CREATE TEMP TABLE _assert_reversible (
    no_competing_same_height_blocks INTEGER NOT NULL
        CHECK (no_competing_same_height_blocks = 1)
);

INSERT INTO _assert_reversible (no_competing_same_height_blocks)
SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM blocks GROUP BY block_height HAVING count(*) > 1
) THEN 1 ELSE 0 END;

DROP TABLE _assert_reversible;

PRAGMA defer_foreign_keys = ON;

ALTER TABLE blocks RENAME TO blocks_old;
ALTER TABLE wallet_sync_states RENAME TO wallet_sync_states_old;
ALTER TABLE transactions RENAME TO transactions_old;
ALTER TABLE transaction_inputs RENAME TO transaction_inputs_old;
ALTER TABLE credits RENAME TO credits_old;
ALTER TABLE active_credit_incidences RENAME TO active_credit_incidences_old;
ALTER TABLE credit_spends RENAME TO credit_spends_old;

-- Restore height as the blocks primary key.
CREATE TABLE blocks (
    block_height INTEGER PRIMARY KEY CHECK (block_height >= 0),
    header_hash BLOB NOT NULL UNIQUE CHECK (length(header_hash) = 32),
    block_timestamp INTEGER NOT NULL CHECK (block_timestamp >= 0)
);

INSERT INTO blocks (block_height, header_hash, block_timestamp)
SELECT block_height, header_hash, block_timestamp FROM blocks_old;

-- Map every surrogate id back to its height.
CREATE TABLE block_id_map (
    block_id INTEGER PRIMARY KEY,
    old_height INTEGER NOT NULL
);

INSERT INTO block_id_map (block_id, old_height)
SELECT id, block_height FROM blocks_old;

-- transactions references height again.
CREATE TABLE transactions (
    id INTEGER PRIMARY KEY,
    wallet_id INTEGER NOT NULL,
    tx_hash BLOB NOT NULL CHECK (length(tx_hash) = 32),
    raw_tx BLOB NOT NULL,
    received_unix INTEGER NOT NULL,
    block_height INTEGER,
    confirmed_order INTEGER CHECK (
        confirmed_order BETWEEN 0 AND 4294967295
    ),
    is_coinbase BOOLEAN NOT NULL CHECK (is_coinbase IN (FALSE, TRUE)),
    UNIQUE (wallet_id, id),
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT,
    FOREIGN KEY (block_height) REFERENCES blocks (block_height)
        ON DELETE RESTRICT,
    CHECK (
        (block_height IS NULL AND confirmed_order IS NULL)
        OR (block_height IS NOT NULL AND confirmed_order IS NOT NULL)
    )
);

INSERT INTO transactions (
    id, wallet_id, tx_hash, raw_tx, received_unix, block_height,
    confirmed_order, is_coinbase
)
SELECT
    t.id, t.wallet_id, t.tx_hash, t.raw_tx, t.received_unix, m.old_height,
    t.confirmed_order, t.is_coinbase
FROM transactions_old AS t
LEFT JOIN block_id_map AS m ON m.block_id = t.block_id;

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

-- Restore height-keyed sync state, keeping the independent birthday verification
-- bit introduced in migration 10.
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
        ON DELETE RESTRICT
);

INSERT INTO wallet_sync_states (
    wallet_id, start_block_height, synced_block_height, birthday_timestamp,
    birthday_block_height, birthday_block_verified
)
SELECT
    s.wallet_id, start_map.old_height, synced_map.old_height,
    s.birthday_timestamp, birthday_map.old_height, s.birthday_block_verified
FROM wallet_sync_states_old AS s
INNER JOIN block_id_map AS start_map ON start_map.block_id = s.start_block_id
INNER JOIN block_id_map AS synced_map ON synced_map.block_id = s.synced_block_id
LEFT JOIN block_id_map AS birthday_map
    ON birthday_map.block_id = s.birthday_block_id;

-- Drop the source tables child-first, then the id mapping.
DROP TABLE credit_spends_old;
DROP TABLE active_credit_incidences_old;
DROP TABLE transaction_inputs_old;
DROP TABLE credits_old;
DROP TABLE transactions_old;
DROP TABLE wallet_sync_states_old;
DROP TABLE blocks_old;
DROP TABLE block_id_map;

-- Recreate every explicit index on the restored tables.
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

CREATE INDEX idx_transaction_inputs_prevout
ON transaction_inputs (prev_tx_hash, prev_output_index, spending_tx_id);

CREATE INDEX idx_credits_wallet_transaction
ON credits (wallet_id, transaction_id, output_index);

CREATE INDEX idx_credits_address
ON credits (wallet_id, address_scope_id, address_id);
