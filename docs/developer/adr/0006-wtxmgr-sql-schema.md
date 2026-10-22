# ADR 0006: Wallet Transaction Manager SQL Schema

## Status

- **Status:** Accepted
- **Date:** 2026-01-28

## Relationships

- **Amends:** None.
- **Supersedes:** None.
- **Amended by:** [ADR 0015](0015-sql-shared-chain-ownership.md) for SQL block
  identity and canonical-frontier semantics.
- **Superseded by:** None.

## 1. Context

The wallet moves from a Key-Value store to a relational SQL backend. As part of
this migration, the Wallet Transaction Manager (`wtxmgr`) requires a new
schema design. The `wtxmgr` tracks these items:
1.  **Transactions:** Immutable blockchain data and user intent.
2.  **UTXOs (Credits):** Outputs that the wallet owns (the primary operational
    unit).
3.  **Spends (Debits):** Inputs that spend those outputs.
4.  **Metadata:** User labels and transient locks (leases).

For a detailed theoretical analysis of the data model, see
[UTXO Data Model and Lifecycle](../utxo_data_model.md).

Note on txid uniqueness: Bitcoin has historical edge cases with duplicate txids
(primarily coinbase). But since BIP30, duplicates cannot create outpoints that
are unspent at the same time. Thus this schema treats `tx_hash` as unique per
wallet for balance and coin selection purposes.

## 2. Decision

We will adopt a **UTXO-Centered, Soft-Deletion Schema**.

### 2.1 Core Principles
1.  **UTXO-Centered Operations:** The schema is optimized for the `Balance()`
    and `CoinSelection()` queries. These queries focus on the `utxos` table.
2.  **Transaction-Centered Integrity:** Validity flows from Parent to Child. A
    UTXO is valid only in one of these conditions:
    *   Its parent Transaction is valid (`tx_status = 1`, `published`).
    *   Its parent Transaction is explicitly allowed for chaining
        (`tx_status = 0`, `pending`).
3.  **Immutable History (Soft Deletion):** We **NEVER** automatically `DELETE`
    rows.
    *   A `tx_status` field marks failed and RBF'd transactions (e.g.,
        `replaced`, `failed`).
    *   These transactions stay in the database for audit history, but balance
        queries exclude them.
    *   Foreign Keys use `ON DELETE RESTRICT` for creation relationships. This
        prevents accidental data loss.
4.  **Wallet-Scoped Rows:** `wallet_id` scopes all `wtxmgr` tables. Thus
    multiple wallets can share a single database without row-level conflicts.

### 2.1.1 Wallet-Scoped vs Global Transactions
We considered two designs:

*   **Wallet-scoped tables (chosen):**
    *   Pros: Simple schema; no join tables; queries stay local to a wallet; no
        need for cross-wallet coordination.
    *   Cons: Duplicates transaction rows across wallets that observe the same
        global tx.
*   **Global transactions table (alternative):**
    *   Pros: Storage efficiency; one canonical row per `tx_hash`.
    *   Cons: Requires additional mapping tables (e.g., `wallet_transactions`)
        for per-wallet ownership and metadata; more complex queries and
        constraints; concurrency semantics that need more care.

This ADR chooses wallet-scoped tables because they are simple and easy to
implement. A future migration to a global transactions table is possible. We
consider that migration a separate architectural decision.

### 2.1.2 Explicit Status vs. Derived Status
We considered two designs to track transaction validity:

*   **Explicit `tx_status` column (chosen):**
    *   The `tx_status` field stores the pre-computed validity state of the
        transaction. The write path sets it atomically when an invalidating
        event occurs (RBF, double-spend, reorg).
    *   The field stores a compact numeric code (`0 = pending`,
        `1 = published`, `2 = replaced`, `3 = failed`, `4 = orphaned`). Thus
        hot-path predicates and indexes do not pay the storage or comparison
        cost of repeated status strings.
    *   The schema intentionally does **not** use a separate status lookup
        table. The status set is tiny, closed, and owned by the application.
        A reference table would add foreign-key and seed-data complexity
        without meaningful flexibility. The numeric status is stored directly
        in each transaction row, which keeps the hot path simple. The Go enum
        layer supplies the human-readable names.
    *   Pros:
        *   Balance and coin-selection queries filter on a single status
            predicate (`tx_status IN (1, 0)`) with no joins. An index is
            possible if profiling justifies it.
        *   The write path does cascading invalidation once, and nothing
            derives it again.
        *   You can query the audit states (`failed`, `replaced`, `orphaned`)
            directly.
    *   Cons: The field can theoretically drift from the underlying facts.
        `CHECK` constraints (`check_confirmed_published`,
        `check_coinbase_confirmation_state`) and coinbase reorg triggers
        partially mitigate this risk. Correct `failed`/`replaced` transitions
        remain a write-path responsibility, and tests validate them.

*   **Derived status from other columns (alternative):**
    *   At coarse granularity (pending vs active vs invalid), you can partly
        derive some states:
        *   `orphaned` = `is_coinbase AND block_height IS NULL`.
        *   You can identify direct `replaced` victims from
            `tx_replacements.replaced_tx_id`.
        *   You cannot derive direct `failed` victims from replacement edges
            alone, because upstream invalidation intentionally records no
            replacement edge.
    *   But a full replacement must preserve the distinct invalid states
        (`replaced`, `failed`, `orphaned`). These states have different
        operational semantics:
        *   RBF (`replaced`) allows a new tx to spend the same inputs again.
        *   An `orphaned` coinbase can recover on reconfirmation.
        *   `failed` (double-spend) is permanent.

        If you collapse these states into a single boolean, you lose
        information that recovery logic and user-facing audit need.
    *   A boolean decomposition (e.g., `is_broadcast` + `is_invalid`) also
        causes problems:
        *   `is_broadcast` does not equal `published`. A tx can be
            valid/published because the wallet received it from the network,
            not because this wallet broadcast it.
        *   Boolean pairs create ambiguous combinations (e.g.,
            `is_broadcast=false, is_invalid=true`) that require additional
            constraints.
    *   A fully-derived alternative that preserves the same information
        requires at least three columns (`is_broadcast`/source marker,
        `invalidation_reason` enum, optional `invalidated_by_tx_id`). That is
        strictly more schema surface than a single `tx_status` column.
    *   Cascading invalidation adds more complexity. Downstream txs whose
        parent became invalid were never directly "replaced." Without a
        pre-computed status, every balance/coin-selection query needs a
        recursive CTE that walks up the ancestor chain. That costs O(depth)
        per tx on the hot path.

This ADR chooses explicit status. Explicit status is the minimal representation
that captures all lifecycle states without ambiguity. The `tx_status` column is
a pre-computed materialization that the write path sets once. Database
constraints/triggers enforce key invariants (confirmation and coinbase
semantics). Write-path logic is responsible for correct `failed`/`replaced`
transitions.

### 2.2 Consistency & Concurrency Model
This design assumes standard SQL ACID guarantees.

*   **Atomic updates:** Explicit SQL transactions MUST perform these
    operations:
    *   Reorg disconnects.
    *   Status transitions (RBF/failure/orphaning).
    *   Lease acquisition.
*   **Leases are the concurrency primitive:** `utxo_leases` supplies an
    application-level lock. The lock prevents concurrent coin selection from
    choosing the same UTXO.
*   **Isolation:** Wallet implementations SHOULD treat coin selection + lease
    acquisition as a single atomic unit. If multiple processes share one
    database, they must rely on database-enforced constraints (primary
    keys/uniques) and transactions. They must not rely on best-effort
    in-memory coordination.

Recommended operational defaults:
*   Prefer to run write paths under `SERIALIZABLE`, and retry on serialization
    failures.
*   If you use weaker isolation (e.g., `READ COMMITTED`), rely on unique
    constraints and single-statement lease acquisition (no read-then-write
    without conflict handling).

### 2.3 Reorg & RBF Strategy
*   **Reorgs:** The `blocks` table represents the current best chain. When a
    block disconnects, `ON DELETE SET NULL` sets `block_height` to `NULL` on
    each transaction that references the block.
    *   **Effect (non-coinbase):** Regular transactions become unconfirmed
        (but stay `published`).
    *   **Coinbase special case:** Coinbase transactions from the disconnected
        block become `orphaned`. A coinbase transaction cannot exist outside
        the block that created it.
    *   **Atomicity requirement:** The coinbase status update MUST occur
        atomically with the disconnect.
        *   PostgreSQL evaluates `CHECK` constraints immediately. This includes
            updates that foreign-key actions such as `ON DELETE SET NULL`
            perform.
        *   You can enforce the coinbase invariant at the database level. In
            that case, a simple `DELETE FROM blocks ...` fails unless the same
            statement updates the coinbase row's `tx_status` to `orphaned`.
        *   Recommended: use a trigger that rewrites coinbase `tx_status`
            during the `block_height -> NULL` update (see 3.5).
    *   **Reconfirmation:** An orphaned coinbase transaction can re-enter the
        best chain. To restore it, set `block_height` and `tx_status = 1`
        (`published`) atomically.
*   **RBF:** The update changes the `utxos.spent_by_tx_id` pointer to the new
    transaction and marks the old transaction as `replaced`.

### 2.4 Implementation Notes

This ADR includes a reference schema. The implementation keeps the same
invariants. But it makes a few deliberate schema choices to match the existing
conventions in `wallet/internal/db/migrations/`.

**Primary keys and wallet scoping**

The reference schema uses composite primary keys (`(wallet_id, id)`). With
these keys, foreign keys can enforce wallet scoping.

In this repository, SQLite tables follow the rowid-backed
`INTEGER PRIMARY KEY` pattern of the existing wallet/account/address schema.
The implementation keeps that convention and also preserves the wallet-scoping
invariant:
1.  It uses single-column primary keys on `id`.
2.  It adds `UNIQUE(wallet_id, id)` constraints on wallet-scoped tables.
3.  Child tables use composite foreign keys that reference `(wallet_id, id)`.

**Manual pruning and `spent_by` semantics**

The reference schema uses `ON DELETE SET NULL` for the
`(wallet_id, spent_by_tx_id)` foreign key. With this action, a physical delete
of a spending transaction can restore a UTXO to the unspent set.

In a composite foreign key, `ON DELETE SET NULL` applies to *all* referencing
columns. Because `utxos.wallet_id` is `NOT NULL`, the schema cannot express the
reference behavior directly as written.

Thus the implementation uses `ON DELETE RESTRICT` for the spender foreign key.
It defines manual pruning as an explicit operation that the application
drives. The operation clears `utxos.spent_by_*` before it deletes/prunes the
spending transaction. All of these steps occur within a single SQL
transaction.

**SQLite coinbase disconnect handling**

A block delete can cause `transactions.block_height` to become `NULL`. In that
case, PostgreSQL can rely on the transaction-row trigger alone.

SQLite evaluates child-row checks before an `AFTER UPDATE` trigger on the child
table can normalize the row. To preserve the coinbase orphaning invariant, the
implementation adds a `BEFORE DELETE ON blocks` trigger. This trigger rewrites
affected transactions into their final disconnected state before SQLite
removes the block row.

**Transaction labels**

User-facing labels are part of the internal store contract (`TxInfo.Label`).
The implementation stores them inline as `transactions.tx_label`, not in a
separate labels table. This choice keeps the hot read path simple.

**Timestamps**

Both PostgreSQL and SQLite now follow the same timestamp contract:

- all persisted timestamps represent UTC instants
- PostgreSQL stores them as `TIMESTAMP`
- SQLite stores them as `TIMESTAMP`/`DATETIME`
- logic-sensitive comparisons (for example lease expiry) use UTC values that
  the caller supplies, and do not rely on session-local database time
  semantics

## 3. Implemented Schema Notes

The SQL migrations under `wallet/internal/db/migrations/postgres` and
`wallet/internal/db/migrations/sqlite` are the source of truth for the concrete
schema. This section records the important design decisions. It does not copy
the full reference DDL, because that copy can drift from the live migrations.

### 3.1 Transactions

- `transactions` stays wallet-scoped through `wallet_id`
- `tx_status` stores the wallet-relative validity state inline as a small,
  closed numeric enum
- `tx_label` stores user-facing labels inline and keeps the hot read path simple
- the schema keeps `raw_tx` because it does not store a fully normalized
  input/output graph; callers still need to reconstruct `wire.MsgTx` for
  transaction reads and dependency walks
- `UNIQUE (wallet_id, id)` stays so wallet-scoped child relations can use a
  composite foreign-key target where needed

### 3.2 UTXOs

- the schema intentionally does not store `utxos.wallet_id`
- wallet ownership comes from the creating transaction:
  `utxos.tx_id -> transactions.wallet_id`
- `address_id` still records the owning address
- correctness requires that the wallet derived from `tx_id` and the wallet
  derived from `address_id` match
- PostgreSQL and SQLite both enforce this invariant with triggers on `utxos`
- a trigger also enforces same-wallet spend edges when `spent_by_tx_id` is
  present

This design keeps the UTXO row normalized and preserves the important
wallet-scoped integrity checks.

### 3.3 Replacement edges

- `tx_replacements` stays wallet-scoped
- both endpoints reference wallet-scoped transaction rows through
  `(wallet_id, id)`
- `created_at` is stored as a UTC `TIMESTAMP`

### 3.4 UTXO leases

- `utxo_leases` keeps `wallet_id` as a query helper for wallet-scoped lease
  scans and cleanup
- `utxo_id` is the key of the row, so one UTXO can have at most one lease row
- a trigger enforces wallet consistency between `utxo_leases.wallet_id` and the
  leased UTXO
- `expires_at` is stored as a UTC `TIMESTAMP`
- lease acquisition, renewal, and cleanup compare against explicit UTC values
  that the caller supplies

### 3.5 Triggers

The implementation uses triggers for the invariants that ordinary foreign keys
alone cannot fully express:

- coinbase disconnect/orphan handling on `transactions`
- `wallet(tx_id) == wallet(address_id)` on `utxos`
- same-wallet `spent_by_tx_id` on `utxos`
- lease wallet consistency on `utxo_leases`

With these triggers, the database protects the critical wallet-scoping rules.
The design does not assume that the application layer is always correct.

## 4. Consequences

### 4.1. True Multi-Wallet Support
The transaction graph stays wallet-scoped. Each wallet-owned row gets its
wallet ownership in one of two ways:
*   `wallet_id` keys the row directly.
*   The row derives its wallet ownership through a wallet-scoped parent
    transaction.

Thus multiple wallets can share the same database without conflicting unique
constraints. The same network outpoint or tx hash can also appear in multiple
wallets independently.

Note: A separate, truly global `transactions` table that wallets share is a
different design. That design requires a join table (e.g.,
`wallet_transactions`) to track per-wallet ownership and metadata.

### 4.2. Native SQL Efficiency
The database calculates balances with `SUM(amount)` over the normalized `utxos`
table. The query uses transaction/account joins and database-side filters, and
it uses native database optimizations.

The schema intentionally does not declare one canonical "spendable balance"
API. Callers can disagree about these rules:
*   pending chaining
*   lease exclusion
*   confirmation thresholds
*   coinbase maturity

### 4.3. Audit Trail
The schema uses soft-deletion style transaction states (`tx_status = 2`,
`replaced`). Thus we keep a complete history of user attempts, including the
attempts that failed. This design is better than previous designs that
physically deleted failed transactions.

### 4.4. Complexity Trade-off
We accept slightly more complexity in **Transaction Reconstruction** (joins of
inputs/outputs). In exchange, we get maximal performance in **Balance
Calculation** and **Coin Selection**, which are the high-frequency operations.

Additional operational consequences:
*   **Pending-chaining is advanced:** Zero-latency chaining should stay an
    application-level choice. Callers that opt into `pending` parents accept
    an operational risk: child transactions depend on a successful broadcast
    of their parents.
*   **Recursive invalidation is unbounded in theory:** After an upstream
    double-spend, the write path marks downstream transactions `failed`. This
    step can require recursive graph traversal. Implementations should assume
    a bounded typical depth, but plan for worst-case behavior (e.g., set a
    maximum recursion depth or iteration limit).

### 4.5 Operational Notes (Out of Scope for This ADR)
This ADR defines the target schema and invariants. Production operations still
require explicit policies and tools:

*   **Pruning:** Define criteria for manual pruning (what can be deleted, and
    how to preserve audit semantics).
*   **Migration:** Define how to migrate from the existing key-value store
    (offline conversion, incremental migration, rollback plan).
*   **Backup/Restore:** Large immutable histories increase backup size and
    restore time. A restore can require revalidation of unconfirmed
    transactions.
    *   After a restore, the wallet should fetch the current mempool again.
        It should also evaluate the RBF/double-spend status of unconfirmed
        transactions again.
*   **Schema evolution:** Future changes should come through versioned
    migrations. Preserve the immutable-history guarantees when you add new
    columns or constraints.

Monitoring note:
*   Track table growth, the count of active leases, and lease cleanup latency.
    These metrics are important for long-running nodes and multi-process
    deployments.
