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

-- Share normalized spend eligibility between recovery and the combined read.
-- Keep leases, accountless imports and credits claimed only by unconfirmed
-- spenders. Funding and its known unconfirmed ancestry must be eligible.
CREATE VIEW outputs_to_watch AS
SELECT
    t.wallet_id,
    t.tx_hash,
    u.output_index,
    t.raw_tx
FROM utxos AS u
INNER JOIN transactions AS t ON u.tx_id = t.id
LEFT JOIN derived_addresses AS da ON u.address_id = da.address_id
LEFT JOIN accounts AS acc ON da.account_id = acc.id
WHERE
    (acc.id IS NULL OR NOT acc.no_chain_sync)
    AND EXISTS (
        SELECT 1 FROM eligible_transactions AS eligible
        WHERE eligible.wallet_id = t.wallet_id AND eligible.id = t.id
    )
    -- Recovery still watches unconfirmed-spent credits; a current block ends it.
    AND NOT EXISTS (
        SELECT 1 FROM tx_inputs AS claim
        INNER JOIN transactions AS spender ON claim.wallet_id = spender.wallet_id AND claim.tx_id = spender.id
        WHERE
            claim.wallet_id = t.wallet_id AND claim.prev_tx_hash = t.tx_hash
            AND claim.prev_output_index = u.output_index AND spender.block_height IS NOT NULL
    );
