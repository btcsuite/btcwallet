-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- utxo_leases stores transient application-level locks over wallet-owned UTXOs.
CREATE TABLE utxo_leases (
    -- Reference to the wallet that owns the leased UTXO.
    wallet_id BIGINT NOT NULL REFERENCES wallets (id) ON DELETE RESTRICT,

    -- The leased UTXO row.
    utxo_id BIGINT PRIMARY KEY,

    -- Caller-provided lock ID. It must stay fixed-width so lease ownership can
    -- be compared without decoding application-specific payloads.
    lock_id BYTEA NOT NULL CHECK (length(lock_id) = 32),

    -- UTC-normalized lease expiration timestamp.
    expires_at TIMESTAMP NOT NULL,

    -- The leased output must exist in the UTXO set. Wallet consistency is
    -- enforced by trigger below.
    CONSTRAINT fkey_utxo_leases_utxo FOREIGN KEY (utxo_id)
    REFERENCES utxos (id) ON DELETE CASCADE
);

-- Optimization for wallet-scoped lease cleanup and active-lease scans.
CREATE INDEX idx_utxo_leases_wallet_expires_at
ON utxo_leases (wallet_id, expires_at);

CREATE FUNCTION assert_utxo_lease_wallet_consistency() RETURNS TRIGGER AS $$
DECLARE
    utxo_wallet_id BIGINT;
BEGIN
    SELECT t.wallet_id INTO utxo_wallet_id
    FROM utxos AS u
    INNER JOIN transactions AS t ON u.tx_id = t.id
    WHERE u.id = NEW.utxo_id;

    IF utxo_wallet_id IS NOT NULL AND NEW.wallet_id != utxo_wallet_id THEN
        RAISE EXCEPTION 'utxo lease wallet must match leased utxo wallet';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_assert_utxo_lease_wallet_consistency_insert
BEFORE INSERT ON utxo_leases
FOR EACH ROW
EXECUTE FUNCTION assert_utxo_lease_wallet_consistency();

CREATE TRIGGER trg_assert_utxo_lease_wallet_consistency_update
BEFORE UPDATE OF wallet_id, utxo_id ON utxo_leases
FOR EACH ROW
EXECUTE FUNCTION assert_utxo_lease_wallet_consistency();
