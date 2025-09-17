-- Blocks table to store blockchain block information.
CREATE TABLE IF NOT EXISTS "addr_blocks" (
    -- Blockchain block height, primary key.
    "height" INTEGER PRIMARY KEY,

    -- Hash of the block.
    "hash" BYTEA NOT NULL,

    -- Timestamp of the block.
    "timestamp" INTEGER NOT NULL
);

-- Unique index for fast lookup and prevent duplicate block hashes.
CREATE UNIQUE INDEX IF NOT EXISTS "addr_uidx_blocks_hash"
    ON "addr_blocks" ("hash");

-- Unique index for fast lookup and prevent duplicate block timestamps.
CREATE UNIQUE INDEX IF NOT EXISTS "addr_uidx_blocks_timestamp"
    ON "addr_blocks" ("timestamp");
