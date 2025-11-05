-- Rollback note: Idempotent by design (using "IF EXISTS").
-- Must succeed even if table already dropped or database in unexpected state.
DROP TABLE IF EXISTS blocks;
