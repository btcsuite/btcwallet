-- The legacy pointer cannot represent multiple eligible claims. Refuse
-- ambiguity atomically rather than choose a winner or discard retained inputs.
CREATE TEMP TABLE tx_input_downgrade_guard (
    ambiguous_count INTEGER CONSTRAINT check_no_ambiguous_input_claims
    CHECK (ambiguous_count = 0)
);
INSERT INTO tx_input_downgrade_guard
SELECT count(*) FROM (
    SELECT u.id
    FROM utxos AS u
    INNER JOIN transactions AS parent ON u.tx_id = parent.id
    INNER JOIN tx_inputs AS claim
        ON
            parent.wallet_id = claim.wallet_id AND parent.tx_hash = claim.prev_tx_hash
            AND u.output_index = claim.prev_output_index
    INNER JOIN eligible_transactions AS live
        ON claim.wallet_id = live.wallet_id AND claim.tx_id = live.id
    GROUP BY u.id
    HAVING count(*) > 1
) AS ambiguous;
DROP TABLE tx_input_downgrade_guard;

-- Adding nullable columns preserves credit IDs and the unchanged lease child.
ALTER TABLE utxos ADD COLUMN spent_by_tx_id INTEGER
CONSTRAINT fkey_utxos_spent_by REFERENCES transactions (id) ON DELETE RESTRICT;
ALTER TABLE utxos ADD COLUMN spent_input_index INTEGER CHECK (spent_input_index >= 0)
CONSTRAINT check_spent_tx_and_index_pair CHECK (
    (spent_by_tx_id IS NULL AND spent_input_index IS NULL)
    OR (spent_by_tx_id IS NOT NULL AND spent_input_index IS NOT NULL)
);
DROP INDEX idx_utxos_amount;
CREATE INDEX idx_utxos_unspent ON utxos (tx_id, amount, output_index)
WHERE spent_by_tx_id IS NULL;
CREATE INDEX idx_utxos_spent_by ON utxos (spent_by_tx_id);

-- Restore the original ownership checks before assigning unique claimants.
DROP TRIGGER trg_assert_utxo_wallet_consistency_insert;
DROP TRIGGER trg_assert_utxo_wallet_consistency_update;
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
        SELECT a.wallet_id
        FROM addresses AS a
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

-- A missing eligible claimant leaves both columns NULL; the guard above
-- guarantees the normalized relation supplies at most one spending input.
UPDATE utxos AS u SET (spent_by_tx_id, spent_input_index) = (
    SELECT
        claim.tx_id,
        claim.input_index
    FROM transactions AS parent
    INNER JOIN tx_inputs AS claim
        ON parent.wallet_id = claim.wallet_id AND parent.tx_hash = claim.prev_tx_hash
    INNER JOIN eligible_transactions AS live
        ON claim.wallet_id = live.wallet_id AND claim.tx_id = live.id
    WHERE parent.id = u.tx_id AND claim.prev_output_index = u.output_index
);
