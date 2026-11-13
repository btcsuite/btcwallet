-- Refuse a lossy downgrade before changing any schema or retained facts.
DO $$
BEGIN
    IF EXISTS (
SELECT u.id
FROM utxos AS u
INNER JOIN transactions AS parent ON u.tx_id = parent.id
INNER JOIN tx_inputs AS claim
    ON claim.wallet_id = parent.wallet_id AND claim.prev_tx_hash = parent.tx_hash
    AND claim.prev_output_index = u.output_index
INNER JOIN eligible_transactions AS live
    ON claim.wallet_id = live.wallet_id AND claim.tx_id = live.id
GROUP BY u.id HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'ambiguous input claims prevent downgrade';
    END IF;
END;
$$;

-- Nullable legacy columns and their paired constraint restore one input owner.
ALTER TABLE utxos
ADD COLUMN spent_by_tx_id BIGINT,
ADD COLUMN spent_input_index INTEGER CHECK (spent_input_index >= 0),
ADD CONSTRAINT fkey_utxos_spent_by FOREIGN KEY (spent_by_tx_id)
REFERENCES transactions (id) ON DELETE RESTRICT,
ADD CONSTRAINT check_spent_tx_and_index_pair CHECK (
    (spent_by_tx_id IS NULL AND spent_input_index IS NULL)
    OR (spent_by_tx_id IS NOT NULL AND spent_input_index IS NOT NULL)
);
DROP INDEX idx_utxos_amount;
CREATE INDEX idx_utxos_unspent ON utxos (tx_id, amount, output_index)
WHERE spent_by_tx_id IS NULL;
CREATE INDEX idx_utxos_spent_by ON utxos (spent_by_tx_id);

-- Restore the original ownership checks before assigning unique claimants.
CREATE OR REPLACE FUNCTION assert_utxo_wallet_consistency() RETURNS TRIGGER AS $$
DECLARE
    creating_wallet_id BIGINT;
    address_wallet_id BIGINT;
    spending_wallet_id BIGINT;
BEGIN
    SELECT t.wallet_id INTO creating_wallet_id
    FROM transactions AS t
    WHERE t.id = NEW.tx_id;

    SELECT a.wallet_id INTO address_wallet_id
    FROM addresses AS a
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

DROP TRIGGER trg_assert_utxo_wallet_consistency_update ON utxos;
CREATE TRIGGER trg_assert_utxo_wallet_consistency_update
BEFORE UPDATE OF tx_id, address_id, spent_by_tx_id ON utxos
FOR EACH ROW EXECUTE FUNCTION assert_utxo_wallet_consistency();

-- The guard guarantees at most one eligible claimant for each owned credit.
UPDATE utxos AS u
SET spent_by_tx_id = claim.tx_id, spent_input_index = claim.input_index
FROM transactions AS parent
INNER JOIN tx_inputs AS claim
    ON parent.wallet_id = claim.wallet_id AND parent.tx_hash = claim.prev_tx_hash
INNER JOIN eligible_transactions AS live
    ON claim.wallet_id = live.wallet_id AND claim.tx_id = live.id
WHERE parent.id = u.tx_id AND claim.prev_output_index = u.output_index;
