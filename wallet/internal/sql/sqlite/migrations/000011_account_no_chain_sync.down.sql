-- Remove the forward trigger before dropping its referenced policy column.
DROP TRIGGER IF EXISTS trg_assert_account_identity_immutable;

ALTER TABLE accounts DROP COLUMN no_chain_sync;

-- Restore the exact pre-migration trigger so older binaries retain all
-- structural account protections after rollback.
CREATE TRIGGER trg_assert_account_identity_immutable
BEFORE UPDATE ON accounts
FOR EACH ROW
WHEN
    new.id != old.id
    OR new.wallet_id != old.wallet_id
    OR new.scope_id != old.scope_id
    OR new.is_derived != old.is_derived
    OR new.account_number IS NOT old.account_number
BEGIN
    SELECT raise(ABORT, 'account identity cannot be changed after creation');
END;
