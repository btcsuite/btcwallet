-- SQLite's ADD COLUMN applies the false default to pre-existing rows while
-- installing the final required column without rebuilding this referenced
-- parent table. The check prevents SQLite's flexible typing from accepting
-- integer values outside the boolean domain.
ALTER TABLE accounts
ADD COLUMN no_chain_sync BOOLEAN NOT NULL DEFAULT FALSE
CHECK (no_chain_sync IN (FALSE, TRUE));

-- Replace the structural identity trigger so the creation-time policy cannot
-- be changed later. IS NOT is SQLite's NULL-safe comparison, complementing the
-- column's independent NOT NULL constraint.
DROP TRIGGER trg_assert_account_identity_immutable;

CREATE TRIGGER trg_assert_account_identity_immutable
BEFORE UPDATE ON accounts
FOR EACH ROW
WHEN
    new.id != old.id
    OR new.wallet_id != old.wallet_id
    OR new.scope_id != old.scope_id
    OR new.is_derived != old.is_derived
    OR new.account_number IS NOT old.account_number
    OR new.no_chain_sync IS NOT old.no_chain_sync
BEGIN
    SELECT raise(ABORT, 'account identity cannot be changed after creation');
END;
