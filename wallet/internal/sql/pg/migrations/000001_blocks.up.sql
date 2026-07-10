-- The blocks table tracks blocks that contain wallet transactions.
CREATE TABLE blocks (
    -- The block height is the natural key for a main-chain position.
    block_height INTEGER PRIMARY KEY CHECK (block_height >= 0),

    -- The header hash identifies the block at this height.
    header_hash BYTEA NOT NULL UNIQUE CHECK (length(header_hash) = 32),

    -- The block timestamp is stored as Unix seconds.
    block_timestamp BIGINT NOT NULL CHECK (block_timestamp >= 0)
);
