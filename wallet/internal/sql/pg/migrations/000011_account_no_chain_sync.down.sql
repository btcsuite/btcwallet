-- Remove the forward trigger before replacing its function so no schema
-- object refers to the policy column when the rollback drops that column.
DROP TRIGGER IF EXISTS trg_assert_account_identity_immutable ON accounts;

CREATE OR REPLACE FUNCTION assert_account_identity_immutable()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.wallet_id IS DISTINCT FROM OLD.wallet_id
        OR NEW.scope_id IS DISTINCT FROM OLD.scope_id
        OR NEW.is_derived IS DISTINCT FROM OLD.is_derived
        OR NEW.account_number IS DISTINCT FROM OLD.account_number THEN

        RAISE EXCEPTION 'account identity cannot be changed after creation'
            USING ERRCODE = '23514'; -- check_violation
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

ALTER TABLE accounts DROP COLUMN no_chain_sync;

-- Restore the exact pre-migration trigger so rolling back retains every
-- structural identity guard understood by an older binary.
CREATE TRIGGER trg_assert_account_identity_immutable
BEFORE UPDATE OF id, wallet_id, scope_id, is_derived, account_number ON accounts
FOR EACH ROW
EXECUTE FUNCTION assert_account_identity_immutable();
