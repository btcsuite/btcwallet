-- Migration note: Intentionally NOT idempotent (no "IF NOT EXISTS").
-- This ensures migration tracking stays accurate and fails loudly if run twice.

-- tx_replacements stores the audit edges between replaced and replacement
-- wallet-scoped transactions.
CREATE TABLE tx_replacements (
    -- Reference to the wallet that owns this replacement edge.
    wallet_id INTEGER NOT NULL REFERENCES wallets (id) ON DELETE RESTRICT,

    -- DB ID of the replacement edge.
    --
    -- SQLite only auto-generates row IDs for a single-column INTEGER PRIMARY
    -- KEY, so this branch uses a rowid-backed key here and keeps the
    -- wallet-scoped `(wallet_id, id)` pair unique through a separate
    -- constraint.
    id INTEGER PRIMARY KEY,

    -- The direct victim transaction in the replacement pair.
    replaced_tx_id INTEGER NOT NULL,

    -- The direct winner transaction in the replacement pair.
    replacement_tx_id INTEGER NOT NULL,

    -- Creation timestamp used for replacement-edge traversal ordering.
    created_at TIMESTAMP NOT NULL DEFAULT current_timestamp,

    -- Secondary unique constraint used for wallet-scoped foreign keys.
    CONSTRAINT uidx_tx_replacements_wallet_id_id UNIQUE (wallet_id, id),

    -- The audit edge must stay inside one wallet-scoped transaction graph.
    CONSTRAINT fkey_tx_replacements_replaced FOREIGN KEY (
        wallet_id, replaced_tx_id
    ) REFERENCES transactions (wallet_id, id) ON DELETE CASCADE,
    CONSTRAINT fkey_tx_replacements_replacement FOREIGN KEY (
        wallet_id, replacement_tx_id
    ) REFERENCES transactions (wallet_id, id) ON DELETE CASCADE,

    -- A transaction cannot replace itself.
    CONSTRAINT check_not_self_replacement CHECK (
        replaced_tx_id != replacement_tx_id
    ),

    -- One directed replacement edge may only be recorded once.
    CONSTRAINT uidx_tx_replacements_edge UNIQUE (
        wallet_id, replaced_tx_id, replacement_tx_id
    )
);

-- Optimization for traversing direct victims from a winner.
CREATE INDEX idx_tx_replacements_by_replacement
ON tx_replacements (wallet_id, replacement_tx_id, created_at, id);

-- Optimization for traversing direct winners from a victim.
CREATE INDEX idx_tx_replacements_by_replaced
ON tx_replacements (wallet_id, replaced_tx_id, created_at, id);
