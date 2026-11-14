-- Keep credit IDs and leases intact; only the obsolete single-spender
-- representation and its associated checks/indexes disappear.
DROP TRIGGER trg_assert_utxo_wallet_consistency_update ON utxos;
DROP INDEX idx_utxos_unspent;
DROP INDEX idx_utxos_spent_by;
ALTER TABLE utxos
DROP CONSTRAINT fkey_utxos_spent_by,
DROP CONSTRAINT check_spent_tx_and_index_pair,
DROP COLUMN spent_by_tx_id,
DROP COLUMN spent_input_index;
CREATE INDEX idx_utxos_amount ON utxos (tx_id, amount, output_index);

-- Retain creator/address ownership validation without a second claim owner.
CREATE OR REPLACE FUNCTION assert_utxo_wallet_consistency() RETURNS TRIGGER AS $$
DECLARE
    creating_wallet_id BIGINT;
    address_wallet_id BIGINT;
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

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_assert_utxo_wallet_consistency_update
BEFORE UPDATE OF tx_id, address_id ON utxos
FOR EACH ROW EXECUTE FUNCTION assert_utxo_wallet_consistency();
