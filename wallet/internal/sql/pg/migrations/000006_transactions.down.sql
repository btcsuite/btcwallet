-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if objects are already dropped or database is in an
-- unexpected state.
DROP TRIGGER IF EXISTS trg_disconnect_transactions_before_block_delete ON wallet_blocks;
DROP FUNCTION IF EXISTS disconnect_transactions_before_block_delete();
DROP TRIGGER IF EXISTS trg_set_coinbase_orphaned_on_disconnect ON transactions;
DROP FUNCTION IF EXISTS set_coinbase_orphaned_on_disconnect();
-- Drop dependent views before the input and transaction relations.
DROP VIEW IF EXISTS conflict_affected_transactions;
DROP VIEW IF EXISTS eligible_transactions;

-- Drop input facts before their parent transaction relation.
DROP TABLE IF EXISTS tx_inputs;
DROP TABLE IF EXISTS transactions;
DROP SEQUENCE IF EXISTS transactions_confirmed_order_seq;
