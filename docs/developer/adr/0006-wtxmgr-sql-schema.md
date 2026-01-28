# ADR 0006: Wallet Transaction Manager SQL Schema

## 1. Context

As part of the migration from a Key-Value store to a relational SQL backend, the Wallet Transaction Manager (`wtxmgr`) requires a new schema design. The `wtxmgr` is responsible for tracking:
1.  **Transactions:** Immutable blockchain data and user intent.
2.  **UTXOs (Credits):** Outputs owned by the wallet (the primary operational unit).
3.  **Spends (Debits):** Inputs that spend those outputs.
4.  **Metadata:** User labels and transient locks (leases).

For a detailed theoretical analysis of the data model, see [UTXO Data Model and Lifecycle](../utxo_data_model.md).

Note on txid uniqueness: Bitcoin has historical txid-duplicate edge cases (primarily coinbase). However, since BIP30, duplicates cannot create concurrently-unspent outpoints. This schema therefore treats `tx_hash` as unique per wallet for balance/coin selection purposes.

## 2. Decision

We will adopt a **UTXO-Centered, Soft-Deletion Schema**.

### 2.1 Core Principles
1.  **UTXO-Centered Operations:** The schema is optimized for `Balance()` and `CoinSelection()` queries, which focus on the `utxos` table.
2.  **Transaction-Centered Integrity:** Validity flows from Parent to Child. A UTXO is only valid if its parent Transaction is valid (`status='published'`) or is explicitly allowed for chaining (`status='pending'`).
3.  **Immutable History (Soft Deletion):** We **NEVER** automatically `DELETE` rows.
    *   Failed/RBF'd transactions are marked with a `status` field (e.g., `replaced`, `failed`).
    *   They remain in the database for audit history but are excluded from balance queries.
    *   Foreign Keys use `ON DELETE RESTRICT` for creation relationships to prevent accidental data loss.
4.  **Wallet-Scoped Rows:** All `wtxmgr` tables are scoped by `wallet_id` to support multiple wallets sharing a single database without row-level conflicts.

### 2.1.1 Wallet-Scoped vs Global Transactions
Two designs were considered:

*   **Wallet-scoped tables (chosen):**
    *   Pros: Simple schema; no join tables; queries stay local to a wallet; avoids cross-wallet coordination.
    *   Cons: Duplicates transaction rows across wallets that observe the same global tx.
*   **Global transactions table (alternative):**
    *   Pros: Storage efficiency; one canonical row per `tx_hash`.
    *   Cons: Requires additional mapping tables (e.g., `wallet_transactions`) for per-wallet ownership/metadata; more complex queries and constraints; more careful concurrency semantics.

This ADR chooses wallet-scoped tables for simplicity and implementability. A future migration to a global transactions table is possible but is considered a separate architectural decision.

### 2.1.2 Explicit Status vs. Derived Status
Two designs were considered for tracking transaction validity:

*   **Explicit `status` column (chosen):**
    *   The `status` field is a pre-computed materialization of the transaction's validity state, set atomically at write time when the invalidating event occurs (RBF, double-spend, reorg).
    *   Pros: Balance and coin-selection queries filter on a single status predicate (`status IN ('published', 'pending')`) with no joins (and can be indexed if profiling justifies it); cascading invalidation is performed once at write time and never re-derived; audit states (`failed`, `replaced`, `orphaned`) are directly queryable.
    *   Cons: Introduces a field that could theoretically drift from the underlying facts. This is partially mitigated by `CHECK` constraints (`check_confirmed_published`, `check_coinbase_confirmation_state`) and coinbase reorg triggers; transition correctness for `failed`/`replaced` remains a write-path responsibility validated by tests.

*   **Derived status from other columns (alternative):**
    *   At coarse granularity (pending vs active vs invalid), most states are derivable: `orphaned` = `is_coinbase AND block_height IS NULL`; `replaced` and `failed` (direct victim) = existence in `tx_replacements.replaced_tx_id`.
    *   However, a full replacement requires preserving the distinct invalid states (`replaced`, `failed`, `orphaned`), which have different operational semantics: RBF (`replaced`) allows re-spending the same inputs with a new tx; `orphaned` coinbase can recover on reconfirmation; `failed` (double-spend) is permanent. Collapsing these into a single boolean loses information needed for recovery logic and user-facing audit.
    *   A boolean decomposition (e.g., `is_broadcast` + `is_invalid`) also introduces problems: `is_broadcast` does not equal `published` — a tx can be valid/published because it was received from the network, not broadcast by this wallet; boolean pairs create ambiguous combinations (e.g., `is_broadcast=false, is_invalid=true`) requiring additional constraints.
    *   A fully-derived alternative that preserves the same information would require at least three columns (`is_broadcast`/source marker, `invalidation_reason` enum, optional `invalidated_by_tx_id`) — strictly more schema surface than a single `status` column.
    *   Cascading invalidation adds further complexity: downstream txs whose parent became invalid were never directly "replaced." Without a pre-computed status, every balance/coin-selection query would need a recursive CTE walking up the ancestor chain — O(depth) per tx on the hot path.

This ADR chooses explicit status as the minimal representation that captures all lifecycle states without ambiguity. The `status` column is a pre-computed materialization set once at write time; database constraints/triggers enforce key invariants (confirmation and coinbase semantics), while write-path logic is responsible for setting `failed`/`replaced` transitions correctly.

### 2.2 Consistency & Concurrency Model
This design assumes standard SQL ACID guarantees.

*   **Atomic updates:** Reorg disconnects, status transitions (RBF/failure/orphaning), and lease acquisition MUST be performed using explicit SQL transactions.
*   **Leases are the concurrency primitive:** `utxo_leases` provides an application-level lock that prevents concurrent coin selection from choosing the same UTXO.
*   **Isolation:** Wallet implementations SHOULD treat coin selection + lease acquisition as a single atomic unit. If multiple processes share one database, they must rely on database-enforced constraints (primary keys/uniques) and transactional semantics rather than best-effort in-memory coordination.

Recommended operational defaults:
*   Prefer running write paths under `SERIALIZABLE` and retry on serialization failures.
*   If using weaker isolation (e.g., `READ COMMITTED`), rely on unique constraints and single-statement lease acquisition (no read-then-write without conflict handling).

### 2.3 Reorg & RBF Strategy
*   **Reorgs:** The `blocks` table represents the current best chain. If a block is disconnected, any referencing transaction will have `block_height` set to `NULL` via `ON DELETE SET NULL`.
    *   **Effect (non-coinbase):** Regular transactions become unconfirmed (but remain `published`).
    *   **Coinbase special case:** Coinbase transactions from the disconnected block are marked `orphaned` (they cannot exist outside the block that created them).
    *   **Atomicity requirement:** The coinbase status update MUST occur atomically with the disconnect.
        *   PostgreSQL evaluates `CHECK` constraints immediately, including updates performed by foreign-key actions such as `ON DELETE SET NULL`.
        *   If you enforce the coinbase invariant at the database level, a simple `DELETE FROM blocks ...` will fail unless the coinbase row's `status` is updated to `orphaned` as part of the same statement.
        *   Recommended: use a trigger to rewrite coinbase `status` during the `block_height -> NULL` update (see 3.6).
    *   **Reconfirmation:** If an orphaned coinbase transaction re-enters the best chain, restoring it requires setting `block_height` and `status='published'` atomically.
*   **RBF:** Handled by updating the `utxos.spent_by_tx_id` pointer to the new transaction and marking the old transaction as `replaced`.

## 3. Reference Schema

### 3.1 Wallet: `transactions`
Stores the provenance of funds for a specific wallet. Acts as the source of truth for Validity (`status`) and Confirmation (`block_height`).

```sql
CREATE TABLE transactions (
    wallet_id BIGINT NOT NULL REFERENCES wallets(id) ON DELETE RESTRICT,
    id BIGSERIAL NOT NULL,
    tx_hash BYTEA NOT NULL CHECK (length(tx_hash) = 32),
    -- Raw transaction bytes. This is typically TOASTed in PostgreSQL.
    -- Hot-path queries (balance/coin selection) SHOULD avoid selecting this column.
    raw_tx BYTEA NOT NULL,
    
    -- Confirmation State:
    -- NULL = Unconfirmed (Mempool)
    -- INT  = Confirmed (Mined)
    -- ON DELETE SET NULL: If block is reorged, tx becomes unconfirmed.
    block_height INTEGER REFERENCES blocks(block_height) ON DELETE SET NULL,
    
    -- Validity State (Soft Deletion):
    -- pending:   Created locally, not yet broadcast.
    -- published: Active in mempool or blockchain (Valid); not necessarily broadcast by this wallet.
    -- replaced:  RBF'd by another transaction (Invalid).
    -- failed:    Double-spent by a competitor (Invalid).
    -- orphaned:  Coinbase tx that was reorged out (Invalid).
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    
    -- Absolute wall clock time, stored in UTC.
    received_time TIMESTAMPTZ NOT NULL,
    is_coinbase BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Composite primary key is intentional: it allows foreign keys to enforce
    -- wallet scoping (preventing cross-wallet references). Do not replace this
    -- with a single-column PK on `id` unless all referencing FKs are also
    -- reworked to maintain the same invariant.
    CONSTRAINT pidx_transactions PRIMARY KEY (wallet_id, id),
    CONSTRAINT uidx_transactions_hash UNIQUE (wallet_id, tx_hash),
    CONSTRAINT valid_status CHECK (status IN ('pending', 'published', 'replaced', 'failed', 'orphaned')),
    -- Invariant: If a transaction is confirmed (mined), it must be 'published'.
    CONSTRAINT check_confirmed_published CHECK (
        block_height IS NULL OR status = 'published'
    ),
    -- Invariant: Coinbase transactions cannot exist in the mempool.
    -- If a coinbase transaction loses its block via a reorg, it becomes orphaned.
    CONSTRAINT check_coinbase_not_pending CHECK (NOT (is_coinbase AND status = 'pending')),
    CONSTRAINT check_coinbase_confirmation_state CHECK (
        NOT is_coinbase OR
        (block_height IS NOT NULL AND status = 'published') OR
        (block_height IS NULL AND status = 'orphaned')
    )
);

-- Optimization for Mempool lookups
CREATE INDEX idx_transactions_unconfirmed
ON transactions (wallet_id, block_height)
WHERE block_height IS NULL;

-- Optimization for "all transactions in block X" queries
CREATE INDEX idx_transactions_by_block
ON transactions (wallet_id, block_height)
WHERE block_height IS NOT NULL;

-- Optimization for "latest transactions" queries
CREATE INDEX idx_transactions_by_received_time
ON transactions (wallet_id, received_time DESC);

-- Optimization for status-based filtering (non-hot path)
-- Optional: profile before enabling (low cardinality)
-- CREATE INDEX idx_transactions_by_status
-- ON transactions (wallet_id, status);
```

### 3.2 Local: `utxos`
The **Single Source of Truth** for wallet balance.
Note: The table keeps the `utxos` name for consistency with wallet abstractions, even though it retains spent rows for audit history (`spent_by_tx_id` marks spent outputs).

```sql
CREATE TABLE utxos (
    wallet_id BIGINT NOT NULL REFERENCES wallets(id) ON DELETE RESTRICT,
    id BIGSERIAL NOT NULL,
    
    -- Creation (OutPoint):
    -- ON DELETE RESTRICT: We NEVER delete confirmed transactions or their UTXOs.
    -- To remove history, the user must explicitly Prune (manual op).
    tx_id BIGINT NOT NULL,
    output_index INTEGER NOT NULL CHECK (output_index >= 0),
    
    amount BIGINT NOT NULL CHECK (amount >= 0),
    -- The output script is stored on the address record (see the address-manager
    -- schema). `addresses.script_pub_key` is expected to be NOT NULL for all
    -- addresses, including HD-derived addresses.
    -- Optional address book reference for indexing and UX.
    -- The `addresses` table is part of the address-manager schema (tracked
    -- separately from this ADR's `wtxmgr` schema).
    --
    -- Note: in the draft address schema (`wallet/internal/db/migrations/*/000006_addresses.up.sql`),
    -- `addresses` is keyed by an `account_id` that is ultimately rooted in a
    -- specific wallet (via key scopes). Implementations must ensure `address_id`
    -- always refers to an address belonging to the same `wallet_id`.
    address_id BIGINT NOT NULL REFERENCES addresses(id) ON DELETE RESTRICT,
    
    -- Spending (Input):
    -- ON DELETE SET NULL: If the spending tx is manually pruned, the UTXO becomes unspent.
    spent_by_tx_id BIGINT,
    -- NULL when unspent; non-NULL when spent (enforced by pair constraint).
    spent_input_index INTEGER CHECK (spent_input_index IS NULL OR spent_input_index >= 0),

    -- Composite primary key is intentional: it allows leases and other
    -- references to enforce wallet scoping.
    CONSTRAINT pidx_utxos PRIMARY KEY (wallet_id, id),
    CONSTRAINT fkey_utxos_tx FOREIGN KEY (wallet_id, tx_id)
        REFERENCES transactions(wallet_id, id) ON DELETE RESTRICT,
    CONSTRAINT fkey_utxos_spent_by FOREIGN KEY (wallet_id, spent_by_tx_id)
        REFERENCES transactions(wallet_id, id) ON DELETE SET NULL,
    
    CONSTRAINT check_spent_tx_and_index_pair CHECK (
        (spent_by_tx_id IS NULL AND spent_input_index IS NULL) OR
        (spent_by_tx_id IS NOT NULL AND spent_input_index IS NOT NULL)
    ),

    CONSTRAINT uidx_utxos_outpoint UNIQUE (wallet_id, tx_id, output_index)
);

-- Optimization for Balance Queries (Index-Only Scan)
CREATE INDEX idx_utxos_unspent ON utxos (address_id, amount) WHERE spent_by_tx_id IS NULL;

-- Optimization for listing all UTXOs for an address (including spent)
CREATE INDEX idx_utxos_by_address ON utxos (address_id);

-- Optimization for finding inputs (debits) of a transaction
CREATE INDEX idx_utxos_spent_by ON utxos(wallet_id, spent_by_tx_id);

-- Optimization for listing all outputs of a transaction
CREATE INDEX idx_utxos_by_tx ON utxos(wallet_id, tx_id);
```

Denormalization note:
*   This schema is normalized: the canonical locking script is stored in the address book (`addresses.script_pub_key`).
*   Joining through `address_id` adds work to the signing/reconstruction path, but keeps the hot UTXO table small and avoids duplicating script data.

Cross-wallet integrity note:
*   Ideally, the database should prevent a `utxos` row from referencing an `address_id` belonging to a different wallet.
*   The strongest enforcement is a composite FK `FOREIGN KEY (wallet_id, address_id) REFERENCES addresses(wallet_id, id)`.
*   If the address-manager schema does not expose `wallet_id` on `addresses`, this invariant must be enforced by application logic.

### 3.3 Audit: `tx_replacements`
Tracks the history of RBF and Double-Spends.

```sql
CREATE TABLE tx_replacements (
    wallet_id BIGINT NOT NULL REFERENCES wallets(id) ON DELETE RESTRICT,
    id BIGSERIAL NOT NULL,
    
    -- ON DELETE CASCADE: Supports Manual Pruning.
    -- If a transaction is physically deleted (to save space),
    -- its audit history is automatically cleaned up to prevent FK violations.
    replaced_tx_id BIGINT NOT NULL,
    replacement_tx_id BIGINT NOT NULL,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Composite primary key is intentional: it enforces wallet scoping.
    CONSTRAINT pidx_tx_replacements PRIMARY KEY (wallet_id, id),
    CONSTRAINT fkey_tx_replacements_replaced FOREIGN KEY (wallet_id, replaced_tx_id)
        REFERENCES transactions(wallet_id, id) ON DELETE CASCADE,
    CONSTRAINT fkey_tx_replacements_replacement FOREIGN KEY (wallet_id, replacement_tx_id)
        REFERENCES transactions(wallet_id, id) ON DELETE CASCADE,
    CONSTRAINT check_not_self_replacement CHECK (replaced_tx_id != replacement_tx_id),
    CONSTRAINT uidx_tx_replacements_edge UNIQUE (wallet_id, replaced_tx_id, replacement_tx_id)
);
```

### 3.4 Local: `utxo_leases`
Transient application locks.

```sql
CREATE TABLE utxo_leases (
    wallet_id BIGINT NOT NULL REFERENCES wallets(id) ON DELETE RESTRICT,
    utxo_id BIGINT NOT NULL,
    external_lock_id BYTEA NOT NULL CHECK (length(external_lock_id) = 32),
    expires_at TIMESTAMPTZ NOT NULL,

    -- Composite primary key is intentional: it enforces wallet scoping.
    CONSTRAINT pidx_utxo_leases PRIMARY KEY (wallet_id, utxo_id),
    CONSTRAINT fkey_utxo_leases_utxo FOREIGN KEY (wallet_id, utxo_id)
        REFERENCES utxos(wallet_id, id) ON DELETE CASCADE
);

-- Optimization for lease cleanup
CREATE INDEX idx_utxo_leases_expires_at ON utxo_leases(expires_at);

-- Lease cleanup is expected to be periodic:
-- DELETE FROM utxo_leases WHERE expires_at <= CURRENT_TIMESTAMP;

-- Lease acquisition is expected to be a single atomic statement.
-- Recommended pattern (PostgreSQL): acquire if absent, renew if same external_lock_id,
-- or steal only if expired.
-- Portability note: SQLite supports UPSERT, but uses different time functions.
-- Prefer `CURRENT_TIMESTAMP` in cross-database examples.
-- The `WHERE` clause in `ON CONFLICT DO UPDATE` is supported in SQLite 3.24.0+; verify compatibility with your target version.
--
-- INSERT INTO utxo_leases (wallet_id, utxo_id, external_lock_id, expires_at)
-- VALUES ($1, $2, $3, CURRENT_TIMESTAMP + $4)
-- ON CONFLICT (wallet_id, utxo_id) DO UPDATE
--   SET external_lock_id = EXCLUDED.external_lock_id,
--       expires_at = EXCLUDED.expires_at
-- WHERE utxo_leases.expires_at <= CURRENT_TIMESTAMP
--    OR utxo_leases.external_lock_id = EXCLUDED.external_lock_id
-- RETURNING expires_at;
--
-- If no row is returned, the UTXO is currently leased by another external_lock_id.

Deadlock avoidance note:
*   When acquiring multiple leases in one transaction, acquire them in a stable order
    (for example sorted by `(wallet_id, utxo_id)`) to reduce deadlock risk.
```

### 3.5 Convenience Views

**`spendable_utxos` View:**
Encapsulates the logic of joining transactions to filter out invalid/failed parents.
Note: Filtering for maturity (Coinbase > 100 confs) is done at the application layer using the exposed `block_height` and `is_coinbase` columns, as Views cannot accept dynamic parameters like `current_height`.

Suggested helper (parameterized query):
*   Expose a query helper that takes `current_height` and filters out immature coinbase outputs:
    *   `WHERE (NOT is_coinbase) OR (current_height - block_height) >= 100`

Important: The view includes `pending` parent transactions to enable zero-latency chaining. This is an advanced mode and should be opt-in for conservative spending policies.

Note: Leases are time-based and depend on the database's current time function. For clarity, the view does not attempt to exclude leased UTXOs. Coin selection MUST exclude active leases (for example using a `NOT EXISTS` subquery against `utxo_leases` where `expires_at > CURRENT_TIMESTAMP`).

```sql
CREATE VIEW spendable_utxos AS
SELECT 
    u.*,
    t.block_height,
    t.is_coinbase,
    t.status as tx_status
FROM utxos u
JOIN transactions t ON t.wallet_id = u.wallet_id AND t.id = u.tx_id
WHERE u.spent_by_tx_id IS NULL
  AND t.status IN ('published', 'pending');
```

### 3.6 Triggers (PostgreSQL)

To enforce the coinbase invariant under `ON DELETE SET NULL`, PostgreSQL needs a trigger because `CHECK` constraints are not deferrable.

Recommended behavior:
*   When `block_height` transitions from `NOT NULL` to `NULL`, and `is_coinbase = TRUE`, automatically rewrite `status = 'orphaned'`.

This can be implemented with a `BEFORE UPDATE` trigger on `transactions`. Foreign-key actions execute as ordinary `UPDATE` statements, and triggers on the referencing table will fire.

Portability note:
*   PostgreSQL: Foreign-key actions (such as `ON DELETE SET NULL`) are performed via ordinary `UPDATE` statements on the referencing table, and triggers on that table will fire.
*   SQLite: Foreign-key actions occur after the parent row operation. If you cannot rely on triggers to rewrite `status` during the FK action, enforce coinbase orphaning with an explicit application-side update in the same SQL transaction as the disconnect.

**SQLite example:** To atomically disconnect a block and orphan its coinbase transactions, run the following within a single transaction:
```sql
BEGIN;
DELETE FROM blocks WHERE block_height = ?;
UPDATE transactions SET status = 'orphaned' WHERE is_coinbase AND block_height IS NULL;
COMMIT;
```

Example sketch:

```sql
CREATE FUNCTION set_coinbase_orphaned_on_disconnect()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.block_height IS NULL AND OLD.block_height IS NOT NULL AND NEW.is_coinbase THEN
        NEW.status := 'orphaned';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_set_coinbase_orphaned_on_disconnect
BEFORE UPDATE OF block_height ON transactions
FOR EACH ROW
EXECUTE FUNCTION set_coinbase_orphaned_on_disconnect();
```

## 4. Consequences

### 4.1. True Multi-Wallet Support
All `wtxmgr` tables are scoped by `wallet_id`. This allows multiple wallets to share the same database without conflicting unique constraints (for example, outpoints and transaction hashes are unique per wallet).

Note: A separate, truly global `transactions` table shared across wallets is a different design. That approach would require a join table (e.g., `wallet_transactions`) to track per-wallet ownership and metadata.

### 4.2. Native SQL Efficiency
Balances are calculated using `SUM(amount)` on the `utxos` table (or `spendable_utxos` view), leveraging database optimizations.

### 4.3. Audit Trail
By using "Soft Deletion" (`status='replaced'`), we maintain a complete history of user attempts, even those that failed. This is superior to previous designs that physically deleted failed transactions.

### 4.4. Complexity Trade-off
We accept slightly more complexity in **Transaction Reconstruction** (joining inputs/outputs) in exchange for maximal performance in **Balance Calculation** and **Coin Selection**, which are the high-frequency operations.

Additional operational consequences:
*   **Pending-chaining is advanced:** The `spendable_utxos` view includes `pending` parents to enable zero-latency chaining. This increases operational risk (child transactions depend on parents being broadcast) and should be disabled for conservative policies.
*   **Recursive invalidation is unbounded in theory:** Marking downstream transactions `failed` after an upstream double-spend can require recursive graph traversal. Implementations should assume bounded typical depth but plan for worst-case behavior (e.g., set a maximum recursion depth or iteration limit).

### 4.5 Operational Notes (Out of Scope for This ADR)
This ADR defines the target schema and invariants. Production operations still require explicit policies and tooling:

*   **Pruning:** Define criteria for manual pruning (what can be deleted, and how to preserve audit semantics).
*   **Migration:** Define how to migrate from the existing key-value store (offline conversion, incremental migration, rollback plan).
*   **Backup/Restore:** Large immutable histories impact backup size and restore time; restores may require revalidation of unconfirmed transactions.
    *   After restore, the wallet should re-fetch the current mempool and re-evaluate RBF/double-spend status for unconfirmed transactions.
*   **Schema evolution:** Future changes should be delivered via versioned migrations; preserve immutable-history guarantees when introducing new columns or constraints.

Monitoring note:
*   Track table growth, count of active leases, and lease cleanup latency. These are important for long-running nodes and multi-process deployments.

## 5. Status

Accepted.
