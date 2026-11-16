-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if objects are already dropped or database is in an
-- unexpected state.
DROP TRIGGER IF EXISTS trg_disconnect_transactions_before_block_delete;
-- Drop dependent views before the input and transaction relations.
DROP VIEW IF EXISTS eligible_transactions;

-- Drop input facts before their parent transaction relation.
DROP TABLE IF EXISTS tx_inputs;
DROP TABLE IF EXISTS transactions;
