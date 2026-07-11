-- Credits include both spent and unspent wallet outputs. Each row belongs to
-- one transaction incidence, since the same transaction may be mined in more
-- than one block.
CREATE TABLE credits (
    id INTEGER PRIMARY KEY,
    wallet_id INTEGER NOT NULL,
    transaction_id INTEGER NOT NULL,
    output_index INTEGER NOT NULL
        CHECK (output_index BETWEEN 0 AND 4294967295),
    amount INTEGER NOT NULL CHECK (amount >= 0),
    pk_script BLOB NOT NULL,
    is_change BOOLEAN NOT NULL CHECK (is_change IN (FALSE, TRUE)),
    address_scope_id INTEGER,
    address_id BLOB CHECK (address_id IS NULL OR length(address_id) = 32),
    UNIQUE (transaction_id, output_index),
    UNIQUE (wallet_id, id),
    FOREIGN KEY (wallet_id, transaction_id)
        REFERENCES transactions (wallet_id, id) ON DELETE CASCADE,
    FOREIGN KEY (wallet_id, address_scope_id, address_id)
        REFERENCES addresses (wallet_id, scope_id, address_hash)
        ON DELETE RESTRICT,
    CHECK (
        (address_scope_id IS NULL AND address_id IS NULL)
        OR (address_scope_id IS NOT NULL AND address_id IS NOT NULL)
    )
);

CREATE INDEX idx_credits_wallet_transaction
ON credits (wallet_id, transaction_id, output_index);

CREATE INDEX idx_credits_address
ON credits (wallet_id, address_scope_id, address_id);

-- One credit incidence is canonical for each active wallet outpoint. This is
-- the SQL equivalent of the legacy unspent value pointing to a mined credit
-- incidence, and prevents duplicate mined incidences from duplicating a UTXO.
CREATE TABLE active_credit_incidences (
    wallet_id INTEGER NOT NULL,
    tx_hash BLOB NOT NULL CHECK (length(tx_hash) = 32),
    output_index INTEGER NOT NULL
        CHECK (output_index BETWEEN 0 AND 4294967295),
    credit_id INTEGER NOT NULL UNIQUE,
    PRIMARY KEY (wallet_id, tx_hash, output_index),
    FOREIGN KEY (wallet_id, credit_id)
        REFERENCES credits (wallet_id, id) ON DELETE CASCADE
);

-- A mined credit's optional debit key identifies the exact transaction
-- incidence and input that spent this credit incidence. Unmined conflicts
-- remain represented by transaction_inputs and do not create debit rows.
CREATE TABLE credit_spends (
    wallet_id INTEGER NOT NULL,
    credit_id INTEGER PRIMARY KEY,
    spending_tx_id INTEGER NOT NULL,
    input_index INTEGER NOT NULL
        CHECK (input_index BETWEEN 0 AND 4294967295),
    UNIQUE (spending_tx_id, input_index),
    FOREIGN KEY (wallet_id, credit_id)
        REFERENCES credits (wallet_id, id) ON DELETE CASCADE,
    FOREIGN KEY (wallet_id, spending_tx_id)
        REFERENCES transactions (wallet_id, id) ON DELETE CASCADE,
    FOREIGN KEY (spending_tx_id, input_index)
        REFERENCES transaction_inputs (spending_tx_id, input_index)
        ON DELETE CASCADE
);
