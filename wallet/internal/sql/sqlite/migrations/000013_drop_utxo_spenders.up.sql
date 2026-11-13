-- Input facts now own claims. Rebuild the credit and sole child together,
-- keeping IDs and lease bytes while foreign-key enforcement remains enabled.
ALTER TABLE utxo_leases RENAME TO utxo_leases_spender_legacy;
ALTER TABLE utxos RENAME TO utxos_spender_legacy;

CREATE TABLE utxos (
    id INTEGER PRIMARY KEY,
    tx_id INTEGER NOT NULL,
    output_index INTEGER NOT NULL CHECK (output_index >= 0),
    amount INTEGER NOT NULL CHECK (amount >= 0),
    address_id INTEGER NOT NULL REFERENCES addresses (id) ON DELETE RESTRICT,
    CONSTRAINT fkey_utxos_tx FOREIGN KEY (tx_id)
    REFERENCES transactions (id) ON DELETE RESTRICT,
    CONSTRAINT uidx_utxos_outpoint UNIQUE (tx_id, output_index)
);
INSERT INTO utxos (id, tx_id, output_index, amount, address_id)
SELECT
    id,
    tx_id,
    output_index,
    amount,
    address_id
FROM utxos_spender_legacy;

CREATE TABLE utxo_leases (
    -- Reference to the wallet that owns the leased UTXO.
    wallet_id INTEGER NOT NULL REFERENCES wallets (id) ON DELETE RESTRICT,

    -- The leased UTXO row.
    utxo_id INTEGER PRIMARY KEY,

    -- Caller-provided lock ID. It must stay fixed-width so lease ownership can
    -- be compared without decoding application-specific payloads.
    lock_id BLOB NOT NULL CHECK (length(lock_id) = 32),

    -- UTC-normalized lease expiration timestamp. NULL marks a lease without
    -- expiry, which lasts until its owner releases it or its spend confirms.
    expires_at TIMESTAMP,

    -- The leased output must exist in the UTXO set. Wallet consistency is
    -- enforced by trigger below.
    CONSTRAINT fkey_utxo_leases_utxo FOREIGN KEY (utxo_id)
    REFERENCES utxos (id) ON DELETE CASCADE
);


INSERT INTO utxo_leases (wallet_id, utxo_id, lock_id, expires_at)
SELECT
    wallet_id,
    utxo_id,
    lock_id,
    expires_at
FROM utxo_leases_spender_legacy;

-- Remove the old FK child first; dropping its parent must never cascade
-- into the new leases, whose FK already points to the replacement credits.
DROP TABLE utxo_leases_spender_legacy;
DROP TABLE utxos_spender_legacy;

-- Replace the obsolete partial unspent index with an input-neutral covering
-- index, preserving address/transaction discovery and lease lookup indexes.
CREATE INDEX idx_utxos_amount ON utxos (tx_id, amount, output_index);
CREATE INDEX idx_utxos_by_address ON utxos (address_id);
CREATE INDEX idx_utxos_by_tx ON utxos (tx_id);
CREATE INDEX idx_utxo_leases_wallet_expires_at
ON utxo_leases (wallet_id, expires_at);

-- Credit ownership and lease wallet consistency remain enforced after rebuild.
CREATE TRIGGER trg_assert_utxo_wallet_consistency_insert
BEFORE INSERT ON utxos
FOR EACH ROW
BEGIN
    SELECT raise(ABORT, 'utxo creating tx wallet and address wallet must match')
    WHERE (
        SELECT t.wallet_id
        FROM transactions AS t
        WHERE t.id = new.tx_id
    ) != (
        SELECT a.wallet_id
        FROM addresses AS a
        WHERE a.id = new.address_id
    );

END;

CREATE TRIGGER trg_assert_utxo_wallet_consistency_update
BEFORE UPDATE OF tx_id, address_id ON utxos
FOR EACH ROW
BEGIN
    SELECT raise(ABORT, 'utxo creating tx wallet and address wallet must match')
    WHERE (
        SELECT t.wallet_id
        FROM transactions AS t
        WHERE t.id = new.tx_id
    ) != (
        SELECT a.wallet_id
        FROM addresses AS a
        WHERE a.id = new.address_id
    );

END;

CREATE TRIGGER trg_assert_utxo_lease_wallet_consistency_insert
BEFORE INSERT ON utxo_leases
FOR EACH ROW
BEGIN
    SELECT raise(ABORT, 'utxo lease wallet must match leased utxo wallet')
    WHERE (
        SELECT t.wallet_id
        FROM utxos AS u
        INNER JOIN transactions AS t ON u.tx_id = t.id
        WHERE u.id = new.utxo_id
    ) != new.wallet_id;
END;

CREATE TRIGGER trg_assert_utxo_lease_wallet_consistency_update
BEFORE UPDATE OF wallet_id, utxo_id ON utxo_leases
FOR EACH ROW
BEGIN
    SELECT raise(ABORT, 'utxo lease wallet must match leased utxo wallet')
    WHERE (
        SELECT t.wallet_id
        FROM utxos AS u
        INNER JOIN transactions AS t ON u.tx_id = t.id
        WHERE u.id = new.utxo_id
    ) != new.wallet_id;
END;
