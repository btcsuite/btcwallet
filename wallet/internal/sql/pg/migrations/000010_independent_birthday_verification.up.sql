-- The legacy address manager retains the verification bit when the birthday
-- block is removed, so the fields must remain independent.
ALTER TABLE wallet_sync_states
DROP CONSTRAINT wallet_sync_states_check;
