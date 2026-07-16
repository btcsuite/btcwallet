-- Funding plans and address/runtime guards. Funding plans group the internally
-- owned utxo_leases under a reservation so a set of leases can be reserved,
-- consumed, released, expired, and recovered atomically. utxo_leases stays the
-- only durable outpoint-exclusion relation: a plan owns leases through the
-- funding_plan_id back-reference added below rather than a second competing
-- outpoint lock. No credit, transaction, or existing lease row is rewritten.

-- One funding plan per (wallet, reservation). The reservation_id is a 32-byte
-- owner token that a plan's own leases reuse as their lock_id, so a plan and its
-- leases share one owner identifier. A plan starts reserved and moves exactly
-- once to a terminal state; committed_tx_id records the transaction a consumed
-- plan funded and is null in every other state.
CREATE TABLE funding_plans (
    id INTEGER PRIMARY KEY,
    wallet_id INTEGER NOT NULL,
    reservation_id BLOB NOT NULL CHECK (length(reservation_id) = 32),
    purpose TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('reserved', 'consumed', 'released', 'expired')
    ),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at >= 0),
    committed_tx_id INTEGER,
    UNIQUE (wallet_id, reservation_id),
    UNIQUE (wallet_id, id),
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT,
    -- A consumed plan references the transaction it funded. The reference is
    -- wallet-scoped and never rewrites or deletes the transaction row.
    FOREIGN KEY (wallet_id, committed_tx_id)
        REFERENCES transactions (wallet_id, id) ON DELETE RESTRICT,
    -- Only a consumed plan may name a committed transaction.
    CHECK (committed_tx_id IS NULL OR status = 'consumed')
);

-- Retention cleanup scans a wallet's terminal plans by their expiry deadline.
CREATE INDEX idx_funding_plans_expiry
ON funding_plans (wallet_id, expires_at);

-- Extend utxo_leases with the plan owner columns. SQLite cannot add a composite
-- foreign key with ALTER TABLE, so the leaf table is rebuilt. No other table
-- references utxo_leases, so nothing smart-retargets to the temporary copy, and
-- copied rows carry a null plan reference so no foreign key is exercised.
ALTER TABLE utxo_leases RENAME TO utxo_leases_old;

CREATE TABLE utxo_leases (
    wallet_id INTEGER NOT NULL,
    tx_hash BLOB NOT NULL CHECK (length(tx_hash) = 32),
    output_index INTEGER NOT NULL
        CHECK (output_index BETWEEN 0 AND 4294967295),
    lock_id BLOB NOT NULL CHECK (length(lock_id) = 32),
    expires_unix INTEGER NOT NULL,
    owner_type TEXT NOT NULL DEFAULT 'external'
        CHECK (owner_type IN ('external', 'funding_plan')),
    funding_plan_id INTEGER,
    PRIMARY KEY (wallet_id, tx_hash, output_index),
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT,
    -- A funding-plan lease is owned by exactly one plan; an external lease has
    -- none. The reference is wallet-scoped and never rewrites the plan row.
    FOREIGN KEY (wallet_id, funding_plan_id)
        REFERENCES funding_plans (wallet_id, id) ON DELETE RESTRICT,
    CHECK (
        (owner_type = 'external' AND funding_plan_id IS NULL)
        OR (owner_type = 'funding_plan' AND funding_plan_id IS NOT NULL)
    )
);

-- Every pre-existing lease is external and keeps its outpoint, owner, and
-- expiry unchanged.
INSERT INTO utxo_leases (
    wallet_id, tx_hash, output_index, lock_id, expires_unix,
    owner_type, funding_plan_id
)
SELECT
    wallet_id, tx_hash, output_index, lock_id, expires_unix,
    'external', NULL
FROM utxo_leases_old;

DROP TABLE utxo_leases_old;

-- Recreate the expiry index only after the old table (and its identically named
-- index) is gone to avoid a name collision.
CREATE INDEX idx_utxo_leases_expiry
ON utxo_leases (wallet_id, expires_unix, tx_hash, output_index);

-- Plan-owned leases are located and cleaned up by their owning plan.
CREATE INDEX idx_utxo_leases_funding_plan
ON utxo_leases (wallet_id, funding_plan_id)
WHERE funding_plan_id IS NOT NULL;

-- Derived addresses are unique by their derivation path so the same
-- (account, branch, index) cannot be materialized twice. Imported addresses
-- carry a null branch and index and are excluded from the constraint.
CREATE UNIQUE INDEX uidx_addresses_derivation_path
ON addresses (wallet_id, scope_id, account_number, branch, address_index)
WHERE branch IS NOT NULL AND address_index IS NOT NULL;
