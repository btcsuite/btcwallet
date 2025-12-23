-- Transaction records - stores tx data for both confirmed and unconfirmed
--
-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.
CREATE TABLE transactions (
    -- Surrogate key for space efficiency in foreign key references.
    -- Auto-incrementing primary key.
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Transaction hash - unique identifier for this transaction (32 bytes).
    -- This is the double SHA256 of the serialized transaction.
    tx_hash BLOB NOT NULL CHECK (length(tx_hash) = 32),

    -- Block height - NULL for unconfirmed (mempool) transactions.
    -- Foreign key to blocks table.
    block_height INTEGER REFERENCES blocks (block_height) ON DELETE CASCADE CHECK (block_height >= 0),

    -- Coinbase flag - true if this is a coinbase transaction (block reward).
    is_coinbase BOOLEAN NOT NULL DEFAULT FALSE,

    -- Timestamp when wallet became aware of the transaction (Unix timestamp).
    -- For unconfirmed: time.Now() when first seen in mempool.
    -- For confirmed: block header timestamp (during sync) or time.Now() (during creation).
    received_timestamp INTEGER NOT NULL CHECK (received_timestamp >= 0),

    -- Serialized transaction data (variable length).
    -- This is the full Bitcoin transaction in wire format.
    serialized_tx BLOB NOT NULL CHECK (length(serialized_tx) > 0),

    -- User-defined label for the transaction.
    -- Optional descriptive text to help identify the transaction's purpose.
    tx_label TEXT NOT NULL DEFAULT '',

    -- In a reorg, a tx hash can appear in multiple blocks. A hash is only
    -- unique within a given block.
    UNIQUE (tx_hash, block_height)
);

-- Unconfirmed transactions must be unique. A partial index on tx_hash where
-- block_height is NULL enforces this.
CREATE UNIQUE INDEX transactions_unconfirmed_hash_idx ON transactions (tx_hash)
WHERE block_height IS NULL;
