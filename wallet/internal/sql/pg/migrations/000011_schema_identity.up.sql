-- The schema identity table records the schema family and generation this
-- database belongs to. The Go gate reads it before running the migration
-- runner and rejects databases created by a different schema family. This
-- migration only creates the table; the family and generation values are owned
-- by the gate, which inserts the single row after the table exists.
CREATE TABLE btcwallet_schema_identity (
    -- A single row identifies the whole database, so the primary key is pinned
    -- to one.
    id INTEGER PRIMARY KEY CHECK (id = 1),

    -- The family string names the schema lineage, such as the salvage schema.
    family TEXT NOT NULL,

    -- The generation increases monotonically as the runtime schema evolves.
    generation BIGINT NOT NULL CHECK (generation >= 0),

    -- The creation time of the marker is stored as Unix seconds.
    created_at BIGINT NOT NULL CHECK (created_at >= 0)
);
