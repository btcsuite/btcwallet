-- Drop the runtime concurrency tables child-first so the result-fact cascade
-- foreign key never fires on live rows.
DROP TABLE IF EXISTS operation_result_facts;
DROP TABLE IF EXISTS operation_journal;
DROP TABLE IF EXISTS wallet_runtime_states;
