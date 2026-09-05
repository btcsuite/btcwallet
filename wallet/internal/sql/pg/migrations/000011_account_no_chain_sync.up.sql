-- Store the account's chain-synchronization policy with a false default so
-- callers that omit the column retain the wallet's existing synchronized
-- behavior. The nullable transition lets populated databases be backfilled
-- explicitly before the final required shape is enforced.
ALTER TABLE accounts ADD COLUMN no_chain_sync BOOLEAN DEFAULT FALSE;

UPDATE accounts SET no_chain_sync = FALSE
WHERE no_chain_sync IS NULL;

ALTER TABLE accounts ALTER COLUMN no_chain_sync SET NOT NULL;

-- Recreate both parts of the identity guard so the creation-time policy cannot
-- be changed later. IS DISTINCT FROM keeps every comparison NULL-safe during
-- migration while the final schema independently rejects NULL values.
DROP TRIGGER trg_assert_account_identity_immutable ON accounts;

CREATE OR REPLACE FUNCTION assert_account_identity_immutable()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.wallet_id IS DISTINCT FROM OLD.wallet_id
        OR NEW.scope_id IS DISTINCT FROM OLD.scope_id
        OR NEW.is_derived IS DISTINCT FROM OLD.is_derived
        OR NEW.account_number IS DISTINCT FROM OLD.account_number
        OR NEW.no_chain_sync IS DISTINCT FROM OLD.no_chain_sync THEN

        RAISE EXCEPTION 'account identity cannot be changed after creation'
            USING ERRCODE = '23514'; -- check_violation
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_assert_account_identity_immutable
BEFORE UPDATE OF id, wallet_id, scope_id, is_derived, account_number,
no_chain_sync ON accounts
FOR EACH ROW
EXECUTE FUNCTION assert_account_identity_immutable();
