-- Block metadata - tracks blocks containing wallet transactions
-- TYPE: Dimension Table (mutable during reorgs - blocks at a height can change)
--
-- ANSWERS:
-- - What is the block hash at a given height?
-- - What was the timestamp of a specific block height?
CREATE TABLE blocks (
    -- Natural key - blockchain height (genesis = 0).
    -- The height value itself is immutable (100 is always 100),
    -- but during reorgs the block at this height can be replaced
    -- (DELETE old row, INSERT new row with same height, different hash).
    block_height INTEGER PRIMARY KEY,

    -- Block header hash - unique identifier for this specific block (32 bytes).
    header_hash BLOB NOT NULL UNIQUE CHECK (length(header_hash) = 32),

    -- Unix timestamp - when the block was mined (seconds since epoch).
    timestamp BIGINT NOT NULL
);
