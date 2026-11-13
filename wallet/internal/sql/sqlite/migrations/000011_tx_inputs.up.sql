-- Retain input facts without changing the existing credit-spender policy.
-- Unknown parents have no credit row, so only the spending transaction is a FK.
CREATE TABLE tx_inputs (
    wallet_id INTEGER NOT NULL REFERENCES wallets (id) ON DELETE RESTRICT,
    tx_id INTEGER NOT NULL,
    input_index INTEGER NOT NULL CHECK (input_index >= 0),
    prev_tx_hash BLOB NOT NULL CHECK (length(prev_tx_hash) = 32),
    prev_output_index INTEGER NOT NULL CHECK (
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
