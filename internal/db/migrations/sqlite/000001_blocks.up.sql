-- Block metadata - tracks blocks containing wallet transactions
--
-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.
CREATE TABLE blocks (
    -- Natural key - blockchain height (genesis = 0).
    -- The height value itself is immutable (100 is always 100),
    -- but during reorgs the block at this height can be replaced
    -- (DELETE old row, INSERT new row with same height, different hash).
    block_height INTEGER PRIMARY KEY CHECK (block_height >= 0),

    -- Block header hash - unique identifier for this specific block (32 bytes).
    header_hash BLOB NOT NULL UNIQUE CHECK (length(header_hash) = 32),

    -- Unix timestamp - when the block was mined (seconds since epoch).
    timestamp INTEGER NOT NULL CHECK (timestamp >= 0)
);
