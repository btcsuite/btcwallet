-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- Monotonic sequence used to preserve the order in which wallet transactions
-- enter confirmed block history, independent of their original row IDs.
CREATE SEQUENCE transactions_confirmed_order_seq;

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
    -- The parent delete trigger clears the confirmation edge before its
    -- composite FK is removed, retaining the transaction's Wallet identity.
    block_height INTEGER,

    -- Monotonic token assigned when a row becomes confirmed. Confirmed range
    -- reads use it as the block-local tie-breaker so rows first seen as
    -- unmined do not sort ahead of earlier transactions in the same block.
    confirmed_order BIGINT,

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

    -- Confirmation edges cannot cross Wallet ownership.
    FOREIGN KEY (wallet_id, block_height)
    REFERENCES wallet_blocks (wallet_id, block_height) ON DELETE RESTRICT,

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

    -- The confirmation-order token is meaningful only while a transaction has
    -- a confirming block.
    CONSTRAINT check_confirmed_order_matches_block CHECK (
        (block_height IS NULL AND confirmed_order IS NULL)
        OR (block_height IS NOT NULL AND confirmed_order IS NOT NULL)
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

ALTER SEQUENCE transactions_confirmed_order_seq OWNED BY
transactions.confirmed_order;

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
ON transactions (wallet_id, block_height, confirmed_order)
WHERE block_height IS NOT NULL;

-- Optimization for rollback/disconnect paths that only know the confirmed block
-- height and then fan out to affected wallet rows.
CREATE INDEX idx_transactions_by_confirmed_height
ON transactions (block_height, wallet_id, confirmed_order)
WHERE block_height IS NOT NULL;

-- Optimization for "latest transactions" queries.
CREATE INDEX idx_transactions_by_received_time
ON transactions (wallet_id, received_time DESC);

-- Clearing a confirmation edge must also clear its order and orphan a
-- coinbase atomically. Both explicit rewind and parent deletion use this hook.
CREATE FUNCTION set_coinbase_orphaned_on_disconnect() RETURNS TRIGGER AS $$
BEGIN
    -- Detect an explicit rewind or the parent delete trigger below.
    IF NEW.block_height IS NULL AND OLD.block_height IS NOT NULL
        THEN
        -- The confirmation-order token belongs to the disconnected block edge.
        NEW.confirmed_order := NULL;

        IF NEW.is_coinbase THEN
            -- Only coinbase rows need status rewriting here. Ordinary
            -- transactions may become unconfirmed while keeping their existing
            -- non-orphaned status.
            NEW.tx_status := 4;
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_set_coinbase_orphaned_on_disconnect
BEFORE UPDATE OF block_height ON transactions
FOR EACH ROW
EXECUTE FUNCTION set_coinbase_orphaned_on_disconnect();

-- A composite SET NULL FK would also erase wallet_id. Clear only the height;
-- the existing child trigger maintains coinbase status and confirmation order.
CREATE FUNCTION disconnect_transactions_before_block_delete() RETURNS TRIGGER AS $$
BEGIN
    UPDATE transactions SET block_height = NULL
    WHERE wallet_id = OLD.wallet_id AND block_height = OLD.block_height;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_disconnect_transactions_before_block_delete
BEFORE DELETE ON wallet_blocks
FOR EACH ROW
EXECUTE FUNCTION disconnect_transactions_before_block_delete();

-- Retain immutable input facts independently of wallet credit discovery.
-- Unknown parents have no credit row, so only the spending transaction is a FK.
CREATE TABLE tx_inputs (
    wallet_id BIGINT NOT NULL REFERENCES wallets (id) ON DELETE RESTRICT,
    tx_id BIGINT NOT NULL,
    input_index BIGINT NOT NULL CHECK (input_index >= 0),
    prev_tx_hash BYTEA NOT NULL CHECK (octet_length(prev_tx_hash) = 32),
    prev_output_index BIGINT NOT NULL CHECK (
        prev_output_index >= 0 AND prev_output_index <= 4294967295
    ),
    CONSTRAINT pidx_tx_inputs PRIMARY KEY (wallet_id, tx_id, input_index),
    CONSTRAINT fkey_tx_inputs_tx FOREIGN KEY (wallet_id, tx_id)
    REFERENCES transactions (wallet_id, id) ON DELETE CASCADE
);

-- Competing transactions may reference the same prevout; the lookup is not
-- unique and remains useful before the referenced credit is discovered.
CREATE INDEX idx_tx_inputs_prevout
ON tx_inputs (wallet_id, prev_tx_hash, prev_output_index);

-- Derive eligibility from retained facts; no pointer or flag can become stale.
-- Correlate ancestry to each requested row so point reads use indexed parents.
CREATE VIEW eligible_transactions AS
SELECT
    t.wallet_id,
    t.id
FROM transactions AS t
WHERE
    t.tx_status IN (0, 1)
    AND (
        t.block_height IS NOT NULL
        OR NOT EXISTS (
            WITH RECURSIVE ancestors (id, tx_status, block_height) AS (
                SELECT
                    t.id,
                    t.tx_status,
                    t.block_height
                UNION
                SELECT
                    parent.id,
                    parent.tx_status,
                    parent.block_height
                FROM ancestors AS ancestor
                INNER JOIN tx_inputs AS claim
                    ON claim.wallet_id = t.wallet_id AND ancestor.id = claim.tx_id
                INNER JOIN transactions AS parent
                    ON parent.wallet_id = t.wallet_id AND claim.prev_tx_hash = parent.tx_hash
                WHERE ancestor.block_height IS NULL AND ancestor.tx_status IN (0, 1)
            )

            SELECT 1 FROM ancestors AS ancestor
            WHERE
                ancestor.tx_status NOT IN (0, 1)
                OR (
                    ancestor.block_height IS NULL
                    AND EXISTS (
                        SELECT 1 FROM tx_inputs AS claim
                        INNER JOIN tx_inputs AS other
                            ON
                                claim.wallet_id = other.wallet_id
                                AND claim.prev_tx_hash = other.prev_tx_hash
                                AND claim.prev_output_index = other.prev_output_index
                                AND claim.tx_id != other.tx_id
                        INNER JOIN transactions AS confirmed
                            ON other.wallet_id = confirmed.wallet_id AND other.tx_id = confirmed.id
                        WHERE
                            claim.wallet_id = t.wallet_id AND claim.tx_id = ancestor.id
                            AND confirmed.block_height IS NOT NULL
                    )
                )
        )
    );

-- Unconfirmed transactions whose inputs, or whose unconfirmed ancestors'
-- inputs, compete with another eligible unconfirmed transaction. Keep their
-- outputs discoverable while excluding conflicting branches from safe totals.
CREATE VIEW conflict_affected_transactions AS
SELECT
    t.wallet_id,
    t.id
FROM transactions AS t
INNER JOIN eligible_transactions AS eligible ON t.wallet_id = eligible.wallet_id AND t.id = eligible.id
WHERE
    t.block_height IS NULL
    AND EXISTS (
        WITH RECURSIVE ancestors (id) AS (
            SELECT t.id
            UNION
            SELECT parent.id
            FROM ancestors AS ancestor
            INNER JOIN tx_inputs AS claim ON claim.wallet_id = t.wallet_id AND ancestor.id = claim.tx_id
            INNER JOIN transactions AS parent
                ON parent.wallet_id = t.wallet_id AND claim.prev_tx_hash = parent.tx_hash
            WHERE parent.block_height IS NULL AND parent.tx_status IN (0, 1)
        )

        SELECT 1 FROM ancestors AS ancestor
        INNER JOIN tx_inputs AS claim ON claim.wallet_id = t.wallet_id AND ancestor.id = claim.tx_id
        INNER JOIN tx_inputs AS other
            ON
                claim.wallet_id = other.wallet_id AND claim.prev_tx_hash = other.prev_tx_hash
                AND claim.prev_output_index = other.prev_output_index AND claim.tx_id != other.tx_id
        INNER JOIN transactions AS peer ON other.wallet_id = peer.wallet_id AND other.tx_id = peer.id
        INNER JOIN eligible_transactions AS live ON peer.wallet_id = live.wallet_id AND peer.id = live.id
        WHERE peer.block_height IS NULL
    );
