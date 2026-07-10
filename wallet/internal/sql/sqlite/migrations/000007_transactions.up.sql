-- Transactions are stored as active mined or unmined incidences.  The legacy
-- store does not retain replaced, failed, or orphaned transaction rows.
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

-- There may be several mined incidences of the same transaction hash, but
-- only one unmined incidence in a wallet.
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

-- Inputs are normalized so one outpoint may have several unmined spenders.
-- This mirrors the legacy unmined-input bucket rather than collapsing the
-- spend relation to one transaction ID on a credit row.
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

CREATE INDEX idx_transaction_inputs_prevout
ON transaction_inputs (prev_tx_hash, prev_output_index, spending_tx_id);

-- Labels are keyed by transaction hash rather than incidence.  They have no
-- transaction foreign key because the legacy label bucket is independent of
-- transaction lifetime.  BLOB preserves arbitrary Go string bytes and makes
-- the 500-byte limit unambiguous.
CREATE TABLE transaction_labels (
    wallet_id INTEGER NOT NULL,
    tx_hash BLOB NOT NULL CHECK (length(tx_hash) = 32),
    label BLOB NOT NULL CHECK (length(label) BETWEEN 1 AND 500),
    PRIMARY KEY (wallet_id, tx_hash),
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT
);
