-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- UTXOs table stores wallet-owned credits (spent and unspent).
CREATE TABLE utxos (
    -- DB ID of the UTXO, primary key.
    id BIGSERIAL PRIMARY KEY,

    -- Creation outpoint (tx_id + output_index).
    tx_id BIGINT NOT NULL,
    output_index INTEGER NOT NULL CHECK (output_index >= 0),

    -- Output amount in satoshis.
    amount BIGINT NOT NULL CHECK (amount >= 0),

    -- Reference to the address record that owns the output.
    --
    -- NOTE: The address-manager schema does not expose wallet_id on addresses,
    -- so ownership is derived via addresses -> accounts -> key_scopes and
    -- enforced by trigger below.
    address_id BIGINT NOT NULL REFERENCES addresses (id) ON DELETE RESTRICT,

    -- Spending input (when spent).
    spent_by_tx_id BIGINT,
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

CREATE FUNCTION assert_utxo_wallet_consistency() RETURNS TRIGGER AS $$
DECLARE
    creating_wallet_id BIGINT;
    address_wallet_id BIGINT;
    spending_wallet_id BIGINT;
BEGIN
    SELECT t.wallet_id INTO creating_wallet_id
    FROM transactions AS t
    WHERE t.id = NEW.tx_id;

    SELECT ks.wallet_id INTO address_wallet_id
    FROM addresses AS a
    INNER JOIN accounts AS acc ON a.account_id = acc.id
    INNER JOIN key_scopes AS ks ON acc.scope_id = ks.id
    WHERE a.id = NEW.address_id;

    IF creating_wallet_id IS NOT NULL
        AND address_wallet_id IS NOT NULL
        AND creating_wallet_id != address_wallet_id THEN
        RAISE EXCEPTION 'utxo creating tx wallet and address wallet must match';
    END IF;

    IF NEW.spent_by_tx_id IS NOT NULL THEN
        SELECT t.wallet_id INTO spending_wallet_id
        FROM transactions AS t
        WHERE t.id = NEW.spent_by_tx_id;

        IF creating_wallet_id IS NOT NULL
            AND spending_wallet_id IS NOT NULL
            AND creating_wallet_id != spending_wallet_id THEN
            RAISE EXCEPTION 'utxo spending tx wallet must match creating tx wallet';
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_assert_utxo_wallet_consistency_insert
BEFORE INSERT ON utxos
FOR EACH ROW
EXECUTE FUNCTION assert_utxo_wallet_consistency();

CREATE TRIGGER trg_assert_utxo_wallet_consistency_update
BEFORE UPDATE OF tx_id, address_id, spent_by_tx_id ON utxos
FOR EACH ROW
EXECUTE FUNCTION assert_utxo_wallet_consistency();
