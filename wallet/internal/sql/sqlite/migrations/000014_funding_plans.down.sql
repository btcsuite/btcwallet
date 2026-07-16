-- Reverse the funding-plan and address/runtime guards. Every durable lease
-- outpoint row is preserved because leases are the exclusion primitive; a
-- plan-owned lease is demoted to a plain external lease as the funding_plans
-- grouping is dropped. No lease exclusion is discarded.

-- Drop the derived-address derivation-path uniqueness.
DROP INDEX IF EXISTS uidx_addresses_derivation_path;

-- Rebuild utxo_leases back to its original owner-less shape, dropping the plan
-- owner columns and the composite foreign key to funding_plans first so the
-- table no longer references funding_plans.
DROP INDEX IF EXISTS idx_utxo_leases_funding_plan;
ALTER TABLE utxo_leases RENAME TO utxo_leases_old;

CREATE TABLE utxo_leases (
    wallet_id INTEGER NOT NULL,
    tx_hash BLOB NOT NULL CHECK (length(tx_hash) = 32),
    output_index INTEGER NOT NULL
        CHECK (output_index BETWEEN 0 AND 4294967295),
    lock_id BLOB NOT NULL CHECK (length(lock_id) = 32),
    expires_unix INTEGER NOT NULL,
    PRIMARY KEY (wallet_id, tx_hash, output_index),
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE RESTRICT
);

INSERT INTO utxo_leases (
    wallet_id, tx_hash, output_index, lock_id, expires_unix
)
SELECT wallet_id, tx_hash, output_index, lock_id, expires_unix
FROM utxo_leases_old;

DROP TABLE utxo_leases_old;

CREATE INDEX idx_utxo_leases_expiry
ON utxo_leases (wallet_id, expires_unix, tx_hash, output_index);

-- utxo_leases no longer references funding_plans, so the grouping table can be
-- dropped without a foreign-key restriction.
DROP TABLE IF EXISTS funding_plans;
