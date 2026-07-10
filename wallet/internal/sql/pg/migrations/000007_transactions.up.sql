-- Transactions are stored as active mined or unmined incidences.  The legacy
-- store does not retain replaced, failed, or orphaned transaction rows.
CREATE TABLE transactions (
    id BIGSERIAL PRIMARY KEY,
    wallet_id BIGINT NOT NULL,
    tx_hash BYTEA NOT NULL CHECK (length(tx_hash) = 32),
    raw_tx BYTEA NOT NULL,
    received_unix BIGINT NOT NULL,
    block_height INTEGER,
    confirmed_order BIGINT CHECK (
        confirmed_order BETWEEN 0 AND 4294967295
    ),
    is_coinbase BOOLEAN NOT NULL,
    UNIQUE (wallet_id, id),
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT,
    FOREIGN KEY (block_height) REFERENCES blocks (block_height)
        ON DELETE RESTRICT,
    CHECK (
        (block_height IS NULL AND confirmed_order IS NULL)
        OR (block_height IS NOT NULL AND confirmed_order IS NOT NULL)
    )
);

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

CREATE TABLE transaction_inputs (
    spending_tx_id BIGINT NOT NULL,
    input_index BIGINT NOT NULL
        CHECK (input_index BETWEEN 0 AND 4294967295),
    prev_tx_hash BYTEA NOT NULL CHECK (length(prev_tx_hash) = 32),
    prev_output_index BIGINT NOT NULL
        CHECK (prev_output_index BETWEEN 0 AND 4294967295),
    PRIMARY KEY (spending_tx_id, input_index),
    FOREIGN KEY (spending_tx_id) REFERENCES transactions (id)
        ON DELETE CASCADE
);

CREATE INDEX idx_transaction_inputs_prevout
ON transaction_inputs (prev_tx_hash, prev_output_index, spending_tx_id);

CREATE TABLE transaction_labels (
    wallet_id BIGINT NOT NULL,
    tx_hash BYTEA NOT NULL CHECK (length(tx_hash) = 32),
    label BYTEA NOT NULL CHECK (length(label) BETWEEN 1 AND 500),
    PRIMARY KEY (wallet_id, tx_hash),
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT
);
