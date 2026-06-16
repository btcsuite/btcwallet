-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- tx_inputs records the previous outpoint spent by every input of a
-- wallet-scoped transaction, including inputs that reference outpoints the
-- wallet does not own.
--
-- The utxos table only tracks wallet-owned outputs, so its spend edges can only
-- discover conflicts that share a wallet-owned parent. A wallet transaction can
-- still be relevant (it pays the wallet or spends a wallet output) while also
-- spending a non-wallet input. Once a confirming transaction spends that same
-- external input, the displaced unmined wallet transaction must be invalidated.
-- This table makes those external-input spend edges queryable so conflict
-- discovery can find the displaced root by input, not only by wallet credit.
CREATE TABLE tx_inputs (
    -- Reference to the wallet that owns the spending transaction.
    wallet_id INTEGER NOT NULL REFERENCES wallets (id) ON DELETE RESTRICT,

    -- DB ID of the input row, primary key (rowid-backed).
    id INTEGER PRIMARY KEY,

    -- The wallet-scoped transaction that contains this input.
    tx_id INTEGER NOT NULL,

    -- Position of this input within the spending transaction.
    input_index INTEGER NOT NULL CHECK (input_index >= 0),

    -- Previous outpoint spent by this input (prev_tx_hash + prev_output_index).
    -- These describe the outpoint on the network, not a wallet-owned row, so
    -- prev_tx_hash is stored even when the wallet does not track that parent.
    prev_tx_hash BLOB NOT NULL CHECK (length(prev_tx_hash) = 32),
    prev_output_index INTEGER NOT NULL CHECK (prev_output_index >= 0),

    -- Input rows follow their spending transaction's lifecycle: they are
    -- removed when the unmined transaction row is deleted and otherwise stay
    -- joined to the transaction's current status for filtering.
    CONSTRAINT fkey_tx_inputs_tx FOREIGN KEY (wallet_id, tx_id)
    REFERENCES transactions (wallet_id, id) ON DELETE CASCADE,

    -- Each spending input is recorded at most once, which keeps input insertion
    -- idempotent across confirm-reuse replays.
    CONSTRAINT uidx_tx_inputs_input UNIQUE (tx_id, input_index)
);

-- Optimization for conflict discovery: find the wallet transactions that spend
-- a given previous outpoint. The active-unmined predicate lives in the query
-- because the spending transaction's status is stored on transactions rather
-- than on this row.
CREATE INDEX idx_tx_inputs_prevout
ON tx_inputs (wallet_id, prev_tx_hash, prev_output_index);

-- Optimization for listing or deleting all inputs of one spending transaction.
CREATE INDEX idx_tx_inputs_by_tx ON tx_inputs (tx_id);
