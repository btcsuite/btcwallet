-- Runtime concurrency state and the idempotent operation journal. This
-- migration adds the wallet runtime-state versions the semantic-commit guards
-- compare and increment, plus the journal and result-fact tables that make a
-- committed semantic operation replay-safe. No existing runtime table is
-- touched.

-- One runtime-state row per wallet holds the monotonic domain version counters.
-- Optimistic-concurrency guards read a version, prepare work outside the write
-- transaction, then increment the version only when it still matches, so an
-- unrelated change to another domain does not invalidate expensive preparation.
-- Every counter starts at zero: existing wallets are backfilled below and new
-- wallets establish the row when they are created.
CREATE TABLE wallet_runtime_states (
    wallet_id BIGINT PRIMARY KEY,
    state_version BIGINT NOT NULL DEFAULT 0 CHECK (state_version >= 0),
    history_epoch BIGINT NOT NULL DEFAULT 0 CHECK (history_epoch >= 0),
    secret_version BIGINT NOT NULL DEFAULT 0 CHECK (secret_version >= 0),
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT
);

-- Backfill a zeroed runtime-state row for every wallet that already exists so a
-- populated database upgraded through this migration satisfies the
-- one-row-per-wallet invariant immediately.
INSERT INTO wallet_runtime_states (wallet_id)
SELECT id FROM wallets;

-- The operation journal records each journaled semantic transaction under its
-- (wallet, domain, operation) key. Stage 3 writes the committed row and its
-- result facts in the same transaction as the domain mutation, so a retry of an
-- already committed operation is served from the journal instead of rerunning
-- the mutation. The status is restricted to the accepted state set:
--   started   - in-transaction only, never durably visible after a commit;
--   committed - the mutation and its result facts are durable;
--   aborted   - the operation failed and left no durable domain change;
--   rejected  - an idempotent durable negative result;
--   expired   - marked by retention cleanup before the row is collected.
CREATE TABLE operation_journal (
    wallet_id BIGINT NOT NULL,
    domain TEXT NOT NULL,
    operation_id BYTEA NOT NULL,
    request_hash BYTEA NOT NULL,
    history_epoch BIGINT NOT NULL CHECK (history_epoch >= 0),
    status TEXT NOT NULL CHECK (
        status IN ('started', 'committed', 'aborted', 'expired', 'rejected')
    ),
    result_ref BYTEA,
    result_hash BYTEA,
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    expires_at BIGINT NOT NULL CHECK (expires_at >= 0),
    PRIMARY KEY (wallet_id, domain, operation_id),
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT,
    -- A committed operation must carry the reference and hash that identify and
    -- commit to its result-fact set; other states leave them null.
    CHECK (
        status <> 'committed'
        OR (result_ref IS NOT NULL AND result_hash IS NOT NULL)
    )
);

-- Retention cleanup scans a wallet's terminal rows by their expiry deadline, so
-- the retention window is indexed by (wallet_id, expires_at).
CREATE INDEX idx_operation_journal_expiry
ON operation_journal (wallet_id, expires_at);

-- Operation result facts hold the ordered, immutable facts that reproduce a
-- committed operation's result after its source rows are gone. result_ref on the
-- journal identifies this fact set and result_hash commits to its canonical
-- order and payloads. The composite foreign key cascades on delete so garbage
-- collection removes an operation's facts together with its journal row.
CREATE TABLE operation_result_facts (
    wallet_id BIGINT NOT NULL,
    domain TEXT NOT NULL,
    operation_id BYTEA NOT NULL,
    ordinal BIGINT NOT NULL CHECK (ordinal >= 0),
    fact_type TEXT NOT NULL,
    fact_key BYTEA,
    fact_payload BYTEA NOT NULL,
    PRIMARY KEY (wallet_id, domain, operation_id, ordinal),
    FOREIGN KEY (wallet_id, domain, operation_id)
        REFERENCES operation_journal (wallet_id, domain, operation_id)
        ON DELETE CASCADE
);
