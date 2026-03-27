-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- Transactions table stores wallet-scoped blockchain transactions and their
-- wallet-relative validity/confirmation state.
CREATE TABLE transactions (
    -- Reference to the wallet that owns this transaction row.
    wallet_id BIGINT NOT NULL REFERENCES wallets (id) ON DELETE RESTRICT,

    -- DB ID of the transaction, primary key.
    id BIGSERIAL PRIMARY KEY,

    -- Secondary unique constraint used as the referenced key for wallet-scoped
    -- child relations such as utxos and tx_replacements.
    CONSTRAINT uidx_transactions_wallet_id_id UNIQUE (wallet_id, id),

    -- Transaction hash (txid) (32 bytes). Unique per wallet.
    tx_hash BYTEA NOT NULL CHECK (length(tx_hash) = 32),

    -- Raw serialized transaction bytes.
    --
    -- The SQL schema does not store a fully normalized input/output graph for
    -- every transaction. Persisting raw_tx lets read paths reconstruct the full
    -- wire.MsgTx when callers need the serialized transaction or when rollback /
    -- invalidation walks need to inspect transaction inputs.
    --
    -- NOTE: Hot-path queries (balance/coin selection) SHOULD avoid selecting
    -- this column.
    raw_tx BYTEA NOT NULL,

    -- Confirmation state:
    -- NULL = Unconfirmed (mempool)
    -- INT  = Confirmed (mined)
    --
    -- ON DELETE SET NULL: If a block is reorged, the transaction becomes
    -- unconfirmed.
    block_height INTEGER REFERENCES blocks (block_height) ON DELETE SET NULL,

    -- Validity state (soft deletion).
    --
    -- Store the status code inline instead of via a lookup table because this
    -- enum is tiny, closed, and appears on hot-path predicates/indexes.
    --
    -- Status codes:
    --   0 = pending
    --   1 = published
    --   2 = replaced
    --   3 = failed
    --   4 = orphaned
    tx_status SMALLINT NOT NULL,

    -- Absolute wall clock time, supplied by the caller and stored in UTC
    -- without timezone info.
    --
    -- NOTE: There is intentionally no DEFAULT current_timestamp here because
    -- import/recovery flows may need to preserve the wallet-observed receive
    -- time instead of the row insertion time.
    received_time TIMESTAMP NOT NULL,

    -- Whether this transaction is a coinbase transaction.
    is_coinbase BOOLEAN NOT NULL DEFAULT FALSE,

    -- Optional user-provided label. Empty string means "no label".
    --
    tx_label VARCHAR(500) NOT NULL DEFAULT '',

    -- Wallet-scoped uniqueness lets different wallets record the same network
    -- txid independently while keeping every child lookup anchored to one
    -- wallet.
    CONSTRAINT uidx_transactions_hash UNIQUE (wallet_id, tx_hash),

    -- Keep the persisted validity state closed over the finite set of states
    -- the store knows how to interpret and transition between.
    CONSTRAINT valid_status CHECK (
        tx_status IN (0, 1, 2, 3, 4)
    ),

    -- Non-coinbase transactions cannot enter the orphaned state. That state is
    -- reserved for coinbase rows that were disconnected from the best chain.
    CONSTRAINT check_orphaned_coinbase_only CHECK (
        tx_status != 4 OR is_coinbase
    ),

    -- A transaction attached to a block is treated as confirmed wallet history.
    -- For confirmed rows, the only valid status is `published`; every other
    -- status represents either unmined local state or disconnected history.
    CONSTRAINT check_confirmed_published CHECK (
        block_height IS NULL OR tx_status = 1
    ),

    -- Coinbase transactions cannot exist in the local-only pre-broadcast state
    -- because they are created by mining, not by wallet authorship.
    CONSTRAINT check_coinbase_not_pending CHECK (
        NOT (is_coinbase AND tx_status = 0)
    ),

    -- Coinbase rows may only be recorded in their mined form or in the
    -- orphaned form produced by a disconnect/reorg transition.
    CONSTRAINT check_coinbase_confirmation_state CHECK (
        NOT is_coinbase
        OR (block_height IS NOT NULL AND tx_status = 1)
        OR (block_height IS NULL AND tx_status = 4)
    )
);

-- Optimization for unmined pending/published transaction lookups.
CREATE INDEX idx_transactions_unconfirmed
ON transactions (wallet_id, block_height)
WHERE block_height IS NULL AND tx_status IN (0, 1);

-- Optimization for wallet-scoped joins into pending/published transactions.
CREATE INDEX idx_transactions_live_by_wallet
ON transactions (wallet_id, id)
WHERE tx_status IN (0, 1);

-- Optimization for wallet-scoped unmined history reads ordered by newest
-- receive time first.
CREATE INDEX idx_transactions_unmined_history
ON transactions (wallet_id, received_time DESC, id DESC)
WHERE block_height IS NULL;

-- Optimization for "all transactions in block X" queries.
CREATE INDEX idx_transactions_by_block
ON transactions (wallet_id, block_height)
WHERE block_height IS NOT NULL;

-- Optimization for rollback/disconnect paths that only know the confirmed block
-- height and then fan out to affected wallet rows.
CREATE INDEX idx_transactions_by_confirmed_height
ON transactions (block_height, wallet_id, id)
WHERE block_height IS NOT NULL;

-- Optimization for "latest transactions" queries.
CREATE INDEX idx_transactions_by_received_time
ON transactions (wallet_id, received_time DESC);

-- Reorg handling for coinbase transactions.
--
-- PostgreSQL checks CHECK constraints immediately. When a block is deleted, the
-- FK `ON DELETE SET NULL` action rewrites child `transactions.block_height`
-- values to NULL. Coinbase rows cannot stay in `published` once that happens,
-- because the schema requires:
--   - coinbase + confirmed block => status = 1 (`published`)
--   - coinbase + no block        => status = 4 (`orphaned`)
--
-- PostgreSQL can solve this on the child-row update path. The FK action causes
-- a real `UPDATE OF block_height ON transactions`, so a BEFORE UPDATE trigger
-- can rewrite the same child row from `(published, block)` to
-- `(orphaned, NULL block)` before the new version is checked.
CREATE FUNCTION set_coinbase_orphaned_on_disconnect() RETURNS TRIGGER AS $$
BEGIN
    -- Detect the disconnect transition caused by the FK action on block delete.
    IF NEW.block_height IS NULL AND OLD.block_height IS NOT NULL
        AND NEW.is_coinbase THEN
        -- Only coinbase rows need rewriting here. Ordinary transactions may
        -- become unconfirmed while keeping their existing non-orphaned status.
        NEW.tx_status := 4;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_set_coinbase_orphaned_on_disconnect
BEFORE UPDATE OF block_height ON transactions
FOR EACH ROW
EXECUTE FUNCTION set_coinbase_orphaned_on_disconnect();
