-- Derive eligibility from retained facts; no pointer or flag can become stale.
-- Correlate ancestry to each requested row so point reads use indexed parents.
CREATE VIEW eligible_transactions AS
SELECT
    t.wallet_id,
    t.id
FROM transactions AS t
WHERE
    t.tx_status IN (0, 1)
    AND (
        t.block_height IS NOT NULL
        OR NOT EXISTS (
            WITH RECURSIVE ancestors (id, tx_status, block_height) AS (
                SELECT
                    t.id,
                    t.tx_status,
                    t.block_height
                UNION
                SELECT
                    parent.id,
                    parent.tx_status,
                    parent.block_height
                FROM ancestors AS ancestor
                INNER JOIN tx_inputs AS claim
                    ON claim.wallet_id = t.wallet_id AND ancestor.id = claim.tx_id
                INNER JOIN transactions AS parent
                    ON parent.wallet_id = t.wallet_id AND claim.prev_tx_hash = parent.tx_hash
                WHERE ancestor.block_height IS NULL AND ancestor.tx_status IN (0, 1)
            )

            SELECT 1 FROM ancestors AS ancestor
            WHERE
                ancestor.tx_status NOT IN (0, 1)
                OR (
                    ancestor.block_height IS NULL
                    AND EXISTS (
                        SELECT 1 FROM tx_inputs AS claim
                        INNER JOIN tx_inputs AS other
                            ON
                                claim.wallet_id = other.wallet_id
                                AND claim.prev_tx_hash = other.prev_tx_hash
                                AND claim.prev_output_index = other.prev_output_index
                                AND claim.tx_id != other.tx_id
                        INNER JOIN transactions AS confirmed
                            ON other.wallet_id = confirmed.wallet_id AND other.tx_id = confirmed.id
                        WHERE
                            claim.wallet_id = t.wallet_id AND claim.tx_id = ancestor.id
                            AND confirmed.block_height IS NOT NULL
                    )
                )
        )
    );

-- Discovery retains alternative change, but safe sums cannot add its branches.
-- Follow only unconfirmed ancestors and eligible peers; confirmation ends doubt.
CREATE VIEW contingent_transactions AS
SELECT
    t.wallet_id,
    t.id
FROM transactions AS t
INNER JOIN eligible_transactions AS eligible ON t.wallet_id = eligible.wallet_id AND t.id = eligible.id
WHERE
    t.block_height IS NULL
    AND EXISTS (
        WITH RECURSIVE ancestors (id) AS (
            SELECT t.id
            UNION
            SELECT parent.id
            FROM ancestors AS ancestor
            INNER JOIN tx_inputs AS claim ON claim.wallet_id = t.wallet_id AND ancestor.id = claim.tx_id
            INNER JOIN transactions AS parent
                ON parent.wallet_id = t.wallet_id AND claim.prev_tx_hash = parent.tx_hash
            WHERE parent.block_height IS NULL AND parent.tx_status IN (0, 1)
        )

        SELECT 1 FROM ancestors AS ancestor
        INNER JOIN tx_inputs AS claim ON claim.wallet_id = t.wallet_id AND ancestor.id = claim.tx_id
        INNER JOIN tx_inputs AS other
            ON
                claim.wallet_id = other.wallet_id AND claim.prev_tx_hash = other.prev_tx_hash
                AND claim.prev_output_index = other.prev_output_index AND claim.tx_id != other.tx_id
        INNER JOIN transactions AS peer ON other.wallet_id = peer.wallet_id AND other.tx_id = peer.id
        INNER JOIN eligible_transactions AS live ON peer.wallet_id = live.wallet_id AND peer.id = live.id
        WHERE peer.block_height IS NULL
    );
