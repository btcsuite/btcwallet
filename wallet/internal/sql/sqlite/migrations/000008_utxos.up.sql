-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- UTXOs table stores wallet-owned credits (spent and unspent).
CREATE TABLE utxos (
    -- DB ID of the UTXO, primary key (rowid-backed).
    id INTEGER PRIMARY KEY,

    -- Creation outpoint (tx_id + output_index).
    tx_id INTEGER NOT NULL,
    output_index INTEGER NOT NULL CHECK (output_index >= 0),

    -- Output amount in satoshis.
    amount INTEGER NOT NULL CHECK (amount >= 0),

    -- Reference to the address record that owns the output.
    --
    -- Address rows expose wallet_id directly, so wallet ownership can be
    -- enforced by trigger without an account join.
    address_id INTEGER NOT NULL REFERENCES addresses (id) ON DELETE RESTRICT,

    -- The creating transaction anchors the outpoint to one wallet-scoped
    -- transaction history.
    CONSTRAINT fkey_utxos_tx FOREIGN KEY (tx_id)
    REFERENCES transactions (id) ON DELETE RESTRICT,

    -- Each wallet-local transaction records a given network outpoint at most
    -- once, which keeps credit insertion idempotent and lets outpoint lookups
    -- resolve to one row.
    CONSTRAINT uidx_utxos_outpoint UNIQUE (tx_id, output_index)
);

-- Cover credit amounts without persisting a second owner for input claims.
CREATE INDEX idx_utxos_amount ON utxos (tx_id, amount, output_index);

-- Optimization for listing all UTXOs for an address (including spent).
CREATE INDEX idx_utxos_by_address ON utxos (address_id);

-- Optimization for listing all outputs of a transaction.
CREATE INDEX idx_utxos_by_tx ON utxos (tx_id);

CREATE TRIGGER trg_assert_utxo_wallet_consistency_insert
BEFORE INSERT ON utxos
FOR EACH ROW
BEGIN
    SELECT raise(ABORT, 'utxo creating tx wallet and address wallet must match')
    WHERE (
        SELECT t.wallet_id
        FROM transactions AS t
        WHERE t.id = new.tx_id
    ) != (
        SELECT a.wallet_id
        FROM addresses AS a
        WHERE a.id = new.address_id
    );

END;

CREATE TRIGGER trg_assert_utxo_wallet_consistency_update
BEFORE UPDATE OF tx_id, address_id ON utxos
FOR EACH ROW
BEGIN
    SELECT raise(ABORT, 'utxo creating tx wallet and address wallet must match')
    WHERE (
        SELECT t.wallet_id
        FROM transactions AS t
        WHERE t.id = new.tx_id
    ) != (
        SELECT a.wallet_id
        FROM addresses AS a
        WHERE a.id = new.address_id
    );

END;
