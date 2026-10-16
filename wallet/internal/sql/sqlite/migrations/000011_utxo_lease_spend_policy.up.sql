-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- Requested spend depth for a confirmation-controlled lease. Zero keeps the
-- wall-clock lease behavior, so existing rows stay timed leases.
ALTER TABLE utxo_leases
ADD COLUMN release_after_spend_confs INTEGER NOT NULL DEFAULT 0
CHECK (release_after_spend_confs BETWEEN 0 AND 4294967295);

-- Spend progress of a confirmation-controlled lease: 0 when no confirmed
-- spend was observed, -1 when an observed spend was disconnected, otherwise
-- the height of the confirmed spend. Timed leases never record progress.
ALTER TABLE utxo_leases
ADD COLUMN confirmed_spend_height INTEGER NOT NULL DEFAULT 0
CHECK (
    confirmed_spend_height BETWEEN -1 AND 2147483647
    AND (release_after_spend_confs > 0 OR confirmed_spend_height = 0)
);

-- Optimization for wallet-scoped spend maturity scans.
CREATE INDEX idx_utxo_leases_spend_maturity
ON utxo_leases (wallet_id, confirmed_spend_height)
WHERE release_after_spend_confs > 0;

-- Record spend progress when a spending transaction gains or loses its block.
-- A block delete clears block_height through
-- trg_disconnect_transactions_before_block_delete, so rollbacks reach this
-- trigger as well as direct confirmation updates.
CREATE TRIGGER trg_track_utxo_lease_spend_on_tx_block
AFTER UPDATE OF block_height ON transactions
FOR EACH ROW
WHEN new.block_height IS NOT old.block_height
BEGIN
    UPDATE utxo_leases
    SET
        confirmed_spend_height = coalesce(new.block_height, -1)
    WHERE
        release_after_spend_confs > 0
        AND utxo_id IN (
            SELECT u.id
            FROM utxos AS u
            WHERE u.spent_by_tx_id = new.id
        );
END;

-- Record spend progress when an already confirmed transaction becomes the
-- spender, for example when a confirmed spend is inserted directly.
CREATE TRIGGER trg_track_utxo_lease_spend_on_utxo_spend
AFTER UPDATE OF spent_by_tx_id ON utxos
FOR EACH ROW
WHEN
    new.spent_by_tx_id IS NOT NULL
    AND new.spent_by_tx_id IS NOT old.spent_by_tx_id
BEGIN
    UPDATE utxo_leases
    SET
        confirmed_spend_height = (
            SELECT t.block_height
            FROM transactions AS t
            WHERE t.id = new.spent_by_tx_id
        )
    WHERE
        utxo_id = new.id
        AND release_after_spend_confs > 0
        AND EXISTS (
            SELECT 1
            FROM transactions AS t
            WHERE
                t.id = new.spent_by_tx_id
                AND t.block_height IS NOT NULL
        );
END;
