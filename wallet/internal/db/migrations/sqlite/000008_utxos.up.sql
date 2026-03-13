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
    -- NOTE: The address-manager schema does not expose wallet_id on addresses,
    -- so ownership is derived via addresses -> accounts -> key_scopes and
    -- enforced by trigger below.
    address_id INTEGER NOT NULL REFERENCES addresses (id) ON DELETE RESTRICT,

    -- Spending input (when spent).
    spent_by_tx_id INTEGER,
    spent_input_index INTEGER CHECK (
        spent_input_index IS NULL OR spent_input_index >= 0
    ),

    -- The creating transaction anchors the outpoint to one wallet-scoped
    -- transaction history.
    CONSTRAINT fkey_utxos_tx FOREIGN KEY (tx_id)
    REFERENCES transactions (id) ON DELETE RESTRICT,

    -- Manual pruning note:
    -- The reference ADR uses ON DELETE SET NULL here to restore spendability
    -- when the spending transaction is physically deleted. This repository
    -- uses ON DELETE RESTRICT and requires an explicit pruning operation that
    -- clears spent_by_* first.
    CONSTRAINT fkey_utxos_spent_by FOREIGN KEY (spent_by_tx_id)
    REFERENCES transactions (id) ON DELETE RESTRICT,

    -- spent_by_tx_id and spent_input_index together model one logical pointer
    -- to the spending input, so they must transition between NULL and non-NULL
    -- as a pair.
    CONSTRAINT check_spent_tx_and_index_pair CHECK (
        (spent_by_tx_id IS NULL AND spent_input_index IS NULL)
        OR (spent_by_tx_id IS NOT NULL AND spent_input_index IS NOT NULL)
    ),

    -- Each wallet-local transaction records a given network outpoint at most
    -- once, which keeps credit insertion idempotent and lets outpoint lookups
    -- resolve to one row.
    CONSTRAINT uidx_utxos_outpoint UNIQUE (tx_id, output_index)
);

-- Optimization for balance queries (index-only scan).
CREATE INDEX idx_utxos_unspent
ON utxos (tx_id, amount, output_index)
WHERE spent_by_tx_id IS NULL;

-- Optimization for listing all UTXOs for an address (including spent).
CREATE INDEX idx_utxos_by_address ON utxos (address_id);

-- Optimization for finding inputs (debits) of a transaction.
CREATE INDEX idx_utxos_spent_by ON utxos (spent_by_tx_id);

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
        SELECT ks.wallet_id
        FROM addresses AS a
        INNER JOIN accounts AS acc ON a.account_id = acc.id
        INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
        WHERE a.id = new.address_id
    );

    SELECT raise(ABORT, 'utxo spending tx wallet must match creating tx wallet')
    WHERE new.spent_by_tx_id IS NOT NULL AND (
        SELECT t.wallet_id
        FROM transactions AS t
        WHERE t.id = new.spent_by_tx_id
    ) != (
        SELECT t.wallet_id
        FROM transactions AS t
        WHERE t.id = new.tx_id
    );
END;

CREATE TRIGGER trg_assert_utxo_wallet_consistency_update
BEFORE UPDATE OF tx_id, address_id, spent_by_tx_id ON utxos
FOR EACH ROW
BEGIN
    SELECT raise(ABORT, 'utxo creating tx wallet and address wallet must match')
    WHERE (
        SELECT t.wallet_id
        FROM transactions AS t
        WHERE t.id = new.tx_id
    ) != (
        SELECT ks.wallet_id
        FROM addresses AS a
        INNER JOIN accounts AS acc ON a.account_id = acc.id
        INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
        WHERE a.id = new.address_id
    );

    SELECT raise(ABORT, 'utxo spending tx wallet must match creating tx wallet')
    WHERE new.spent_by_tx_id IS NOT NULL AND (
        SELECT t.wallet_id
        FROM transactions AS t
        WHERE t.id = new.spent_by_tx_id
    ) != (
        SELECT t.wallet_id
        FROM transactions AS t
        WHERE t.id = new.tx_id
    );
END;
