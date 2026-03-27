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
2.  **Transaction-Centered Integrity:** Validity flows from Parent to Child. A UTXO is only valid if its parent Transaction is valid (`tx_status = 1`, `published`) or is explicitly allowed for chaining (`tx_status = 0`, `pending`).
3.  **Immutable History (Soft Deletion):** We **NEVER** automatically `DELETE` rows.
    *   Failed/RBF'd transactions are marked with a `tx_status` field (e.g., `replaced`, `failed`).
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

*   **Explicit `tx_status` column (chosen):**
    *   The `tx_status` field is a pre-computed materialization of the transaction's validity state, set atomically at write time when the invalidating event occurs (RBF, double-spend, reorg).
    *   It is stored as a compact numeric code (`0 = pending`, `1 = published`, `2 = replaced`, `3 = failed`, `4 = orphaned`) so hot-path predicates and indexes do not pay the storage or comparison cost of repeated status strings.
    *   The schema intentionally does **not** use a separate status lookup table. The status set is tiny, closed, and application-owned, so a reference table would add foreign-key and seed-data complexity without adding meaningful flexibility. Keeping the code inline on the transaction row preserves hot-path simplicity, while the Go enum layer provides the human-readable names.
    *   Pros: Balance and coin-selection queries filter on a single status predicate (`tx_status IN (1, 0)`) with no joins (and can be indexed if profiling justifies it); cascading invalidation is performed once at write time and never re-derived; audit states (`failed`, `replaced`, `orphaned`) are directly queryable.
    *   Cons: Introduces a field that could theoretically drift from the underlying facts. This is partially mitigated by `CHECK` constraints (`check_confirmed_published`, `check_coinbase_confirmation_state`) and coinbase reorg triggers; transition correctness for `failed`/`replaced` remains a write-path responsibility validated by tests.

*   **Derived status from other columns (alternative):**
    *   At coarse granularity (pending vs active vs invalid), some states are partly derivable: `orphaned` = `is_coinbase AND block_height IS NULL`; direct `replaced` victims can be identified from `tx_replacements.replaced_tx_id`. Direct `failed` victims are not derivable from replacement edges alone because upstream invalidation intentionally records no replacement edge.
    *   However, a full replacement requires preserving the distinct invalid states (`replaced`, `failed`, `orphaned`), which have different operational semantics: RBF (`replaced`) allows re-spending the same inputs with a new tx; `orphaned` coinbase can recover on reconfirmation; `failed` (double-spend) is permanent. Collapsing these into a single boolean loses information needed for recovery logic and user-facing audit.
    *   A boolean decomposition (e.g., `is_broadcast` + `is_invalid`) also introduces problems: `is_broadcast` does not equal `published` — a tx can be valid/published because it was received from the network, not broadcast by this wallet; boolean pairs create ambiguous combinations (e.g., `is_broadcast=false, is_invalid=true`) requiring additional constraints.
    *   A fully-derived alternative that preserves the same information would require at least three columns (`is_broadcast`/source marker, `invalidation_reason` enum, optional `invalidated_by_tx_id`) — strictly more schema surface than a single `tx_status` column.
    *   Cascading invalidation adds further complexity: downstream txs whose parent became invalid were never directly "replaced." Without a pre-computed status, every balance/coin-selection query would need a recursive CTE walking up the ancestor chain — O(depth) per tx on the hot path.

This ADR chooses explicit status as the minimal representation that captures all lifecycle states without ambiguity. The `tx_status` column is a pre-computed materialization set once at write time; database constraints/triggers enforce key invariants (confirmation and coinbase semantics), while write-path logic is responsible for setting `failed`/`replaced` transitions correctly.

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
        *   If you enforce the coinbase invariant at the database level, a simple `DELETE FROM blocks ...` will fail unless the coinbase row's `tx_status` is updated to `orphaned` as part of the same statement.
        *   Recommended: use a trigger to rewrite coinbase `tx_status` during the `block_height -> NULL` update (see 3.5).
    *   **Reconfirmation:** If an orphaned coinbase transaction re-enters the best chain, restoring it requires setting `block_height` and `tx_status = 1` (`published`) atomically.
*   **RBF:** Handled by updating the `utxos.spent_by_tx_id` pointer to the new transaction and marking the old transaction as `replaced`.

### 2.4 Implementation Notes

This ADR includes a reference schema. The implementation keeps the same
invariants, but makes a few deliberate schema choices to match the existing
conventions in `wallet/internal/db/migrations/`.

**Primary keys and wallet scoping**

The reference schema uses composite primary keys (`(wallet_id, id)`) to make
wallet scoping enforceable with foreign keys.

In this repository, SQLite tables follow the rowid-backed
`INTEGER PRIMARY KEY` pattern used by the existing wallet/account/address
schema. To preserve the wallet-scoping invariant while keeping that
convention, the implementation uses single-column primary keys on `id` and
adds `UNIQUE(wallet_id, id)` constraints on wallet-scoped tables. Child tables
then use composite foreign keys referencing `(wallet_id, id)`.

**Manual pruning and `spent_by` semantics**

The reference schema uses `ON DELETE SET NULL` for the
`(wallet_id, spent_by_tx_id)` foreign key so that physically deleting a
spending transaction can restore a UTXO to the unspent set.

In a composite foreign key, `ON DELETE SET NULL` applies to *all* referencing
columns. With `utxos.wallet_id` being `NOT NULL`, the reference behavior cannot
be expressed directly as written.

The implementation therefore uses `ON DELETE RESTRICT` for the spender foreign
key and defines manual pruning as an explicit, application-driven operation
that clears `utxos.spent_by_*` before deleting/pruning the spending
transaction, all within a single SQL transaction.

**SQLite coinbase disconnect handling**

PostgreSQL can rely on the transaction-row trigger alone when a block delete
causes `transactions.block_height` to become `NULL`.

SQLite evaluates child-row checks before an `AFTER UPDATE` trigger on the child
table can normalize the row. To preserve the coinbase orphaning invariant, the
implementation adds a `BEFORE DELETE ON blocks` trigger that rewrites affected
transactions into their final disconnected state before the block row is
removed.

**Transaction labels**

User-facing labels are part of the internal store contract (`TxInfo.Label`).
The implementation stores them inline as `transactions.tx_label` instead of a
separate labels table to keep the hot read path simple.

**Timestamps**

Both PostgreSQL and SQLite now follow the same timestamp contract:

- all persisted timestamps represent UTC instants
- PostgreSQL stores them as `TIMESTAMP`
- SQLite stores them as `TIMESTAMP`/`DATETIME`
- logic-sensitive comparisons (for example lease expiry) use caller-supplied UTC
  values instead of relying on session-local database time semantics

## 3. Implemented Schema Notes

The SQL migrations under `wallet/internal/db/migrations/postgres` and
`wallet/internal/db/migrations/sqlite` are the source of truth for the concrete
schema. This section captures the important design decisions without duplicating
full reference DDL that can drift from the live migrations.

### 3.1 Transactions

- `transactions` remains wallet-scoped through `wallet_id`
- `tx_status` stores the wallet-relative validity state inline as a small,
  closed numeric enum
- `tx_label` stores user-facing labels inline and keeps the hot read path simple
- `raw_tx` is retained because the schema does not store a fully normalized
  input/output graph; callers still need to reconstruct `wire.MsgTx` for
  transaction reads and dependency walks
- `UNIQUE (wallet_id, id)` remains so wallet-scoped child relations can use a
  composite foreign-key target where needed

### 3.2 UTXOs

- `utxos.wallet_id` is intentionally not stored
- wallet ownership is derived from the creating transaction:
  `utxos.tx_id -> transactions.wallet_id`
- the owning address is still recorded through `address_id`
- correctness requires the wallet derived from `tx_id` and the wallet derived
  from `address_id` to match
- PostgreSQL and SQLite both enforce this invariant with triggers on `utxos`
- same-wallet spend edges are also enforced by trigger when `spent_by_tx_id` is
  present

This keeps the UTXO row normalized while preserving the important wallet-scoped
integrity checks.

### 3.3 Replacement edges

- `tx_replacements` remains wallet-scoped
- both endpoints reference wallet-scoped transaction rows through
  `(wallet_id, id)`
- `created_at` is stored as a UTC `TIMESTAMP`

### 3.4 UTXO leases

- `utxo_leases` keeps `wallet_id` as a query helper for wallet-scoped lease
  scans and cleanup
- the row is keyed by `utxo_id`, so one UTXO can have at most one lease row
- wallet consistency between `utxo_leases.wallet_id` and the leased UTXO is
  enforced by trigger
- `expires_at` is stored as a UTC `TIMESTAMP`
- lease acquisition, renewal, and cleanup compare against explicit UTC values
  supplied by the caller

### 3.5 Triggers

The implementation relies on triggers for the invariants that cannot be fully
expressed through ordinary foreign keys alone:

- coinbase disconnect/orphan handling on `transactions`
- `wallet(tx_id) == wallet(address_id)` on `utxos`
- same-wallet `spent_by_tx_id` on `utxos`
- lease wallet consistency on `utxo_leases`

This keeps the database responsible for protecting the critical wallet-scoping
rules rather than assuming the application layer is always correct.

## 4. Consequences

### 4.1. True Multi-Wallet Support
The transaction graph remains wallet-scoped, and every wallet-owned row is
either directly keyed by `wallet_id` or derives its wallet ownership through a
wallet-scoped parent transaction. This allows multiple wallets to share the
same database without conflicting unique constraints while still permitting the
same network outpoint or tx hash to appear in multiple wallets independently.

Note: A separate, truly global `transactions` table shared across wallets is a different design. That approach would require a join table (e.g., `wallet_transactions`) to track per-wallet ownership and metadata.

### 4.2. Native SQL Efficiency
Balances are calculated using `SUM(amount)` over the normalized `utxos` table
with transaction/account joins and database-side filtering, leveraging native
database optimizations.

The schema intentionally stops short of declaring one canonical "spendable
balance" API because callers may disagree about pending chaining, lease
exclusion, confirmation thresholds, or coinbase maturity rules.

### 4.3. Audit Trail
By using soft-deletion style transaction states (`tx_status = 2`, `replaced`),
we maintain a complete history of user attempts, even those that failed. This
is superior to previous designs that physically deleted failed transactions.

### 4.4. Complexity Trade-off
We accept slightly more complexity in **Transaction Reconstruction** (joining inputs/outputs) in exchange for maximal performance in **Balance Calculation** and **Coin Selection**, which are the high-frequency operations.

Additional operational consequences:
*   **Pending-chaining is advanced:** Zero-latency chaining should remain an
    application-level choice. Callers that opt into `pending` parents take on
    the operational risk that child transactions depend on parents being
    broadcast successfully.
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
