# ADR 0015: SQL Transaction and UTXO Integrity

## Status

- **Status:** Accepted
- **Date:** 2026-08-26

## Relationships

- **Amends:** None.
- **Supersedes:** [ADR 0006](./0006-wtxmgr-sql-schema.md).
- **Amended by:** None.
- **Superseded by:** None.

## 1. Problem

The SQL wallet needs one portable owner for every transaction-graph, wallet,
and spend relation. The current code works, but its schema reconstructs inputs
from raw transactions and cannot prove that a stored spender names the exact
input that spends a UTXO. Independent schema tasks could therefore choose
constraints or mutation orders that do not compose.

## 2. Context

Transactions are wallet-relative, blocks are global, and raw transaction bytes
remain necessary for wire reconstruction. Current UTXO tenancy and spend
consistency also depend partly on application logic and backend-specific
triggers. This decision defines the target shared by SQLite and PostgreSQL; it
does not change the current schema or runtime.

### Constraints

- Every input, including an external or coinbase input, has a graph row.
- Network outpoint identity, local parent identity, and wallet ownership remain
  separate facts.
- Active spend relations never point to terminal transactions.
- Invalid transaction and input history remains available for graph traversal.
- All graph-changing events are atomic.
- Persisted times are UTC instants compared against caller-supplied UTC values.

## 3. Decision

### Wallet and graph ownership

Transactions, inputs, replacement edges, UTXOs, addresses, and leases carry
matching wallet keys across their relations. A UTXO stores its wallet key
directly rather than deriving it through backend-specific triggers. Blocks
remain global.

Every wire input has one normalized row containing its wallet, spending
transaction, input position, previous transaction hash, and previous output
index. Input positions and previous output indexes cover the full unsigned
32-bit wire range. A nullable local-parent ID may be set only when the matching
transaction exists in the same wallet and has the recorded hash.

Raw bytes remain the wire authority. Normalized inputs are the relational
authority for dependency, descendant, conflict, and leaf traversal. Ingestion
writes both representations atomically, and replay must prove that they agree.

### Exact spend identity

A non-null UTXO spend relation identifies one normalized input and proves all
of the following:

- the UTXO and input belong to the same wallet;
- the spending transaction and input position identify that input;
- the input's local parent is the UTXO's creating transaction; and
- the input's previous output index is the UTXO's output index.

The spender fields transition together. One UTXO has at most one current
spender, one input cannot own two UTXO spends, and only a `pending` or
`published` input may own a spend.

### Late parents

Child-first ingestion records the complete previous outpoint with a null local
parent and does not guess ownership. Initial ingestion attaches a spend only
when the active input and wallet-owned parent output are already known.

Late-parent enrichment is the only later operation allowed to fill the local
parent or attach the corresponding UTXO. It matches the stored outpoint,
rejects cross-wallet or conflicting relations, is idempotent, and never revives
a terminal spender.

### Mutation ownership

Each lifecycle transition has one event-shaped owner:

- direct and batch ingestion own transaction rows, raw bytes, complete input
  composition, created UTXOs, and initial known-parent spend attachment;
- late-parent enrichment owns later parent resolution and spend attachment;
- confirmed-conflict handling owns losing-spend clearing, winning-spend
  assignment, terminal status, and direct replacement edges;
- explicit invalidation owns descendant discovery, terminal status, and spend
  clearing for its affected branch;
- rewind and rollback own confirmation detachment, coinbase orphaning,
  descendant failure, and spends cleared by those terminal transitions;
- `DeleteTx` owns removal of an active unmined leaf, clearing its parent spends,
  deleting its created UTXOs and inputs, and deleting the transaction last;
- lease operations own only lease acquisition, renewal, expiry, and release;
  and
- row-local updates cannot rewrite raw bytes, inputs, UTXO ownership, or spend
  relations.

Shared primitives may execute these mutations, but the calling graph event
decides whether a transition is valid. Restrictive relations make missing
cleanup fail atomically instead of silently erasing or detaching graph data.

Terminal transactions, their inputs, and direct replacement history remain
stored. Ordinary physical deletion is limited to the ordered leaf path above.

## 4. Rationale

Normalized inputs preserve the complete graph without claiming that every
previous output belongs to the wallet. Exact spend identity lets both SQL
dialects reject a pointer to the wrong input or outpoint. Stored wallet keys
allow the same composite relations on both backends, while event ownership
prevents competing paths from rewriting the same transition.

## 5. Alternatives Considered

### Amend ADR 0006

ADR 0006 is an accepted historical schema record. This decision replaces its
derived UTXO tenancy, raw-only graph, spender identity, and deletion rules, so
supersession is clearer than rewriting or partially amending it.

### Keep raw transactions as the graph

Decoding raw bytes can reproduce edges but cannot make input identity or spend
integrity declarative. It also leaves every graph mutation path responsible for
reconstructing the same facts.

### Reference only a transaction and input position

That relation proves an input exists, but not that it spends the marked UTXO.
The exact previous outpoint must participate in the relation.

## 6. Consequences

### Positive

- SQLite and PostgreSQL share one integrity and mutation contract.
- Child-first and external inputs remain complete and unambiguous.
- Wrong-wallet, wrong-input, and terminal-spender relations are rejected.
- Follow-up tasks have non-overlapping implementation boundaries.

### Negative and Risks

- UTXO wallet keys and normalized inputs duplicate derivable information.
- Migration must validate existing data instead of hiding inconsistencies.
- Raw bytes and normalized input rows must remain atomically equivalent.
- Current schemas remain transitional until the follow-up tasks land.

## 7. Implementation Overview

This ADR makes no code or schema change. Follow-up work will add stored wallet
keys and normalized inputs, validate and backfill existing data, dual-write raw
and normalized input facts, cut graph readers over, and finally constrain
spends to exact active inputs. Both SQL dialects must expose the same relations,
rejection cases, and event ordering.

The implementation boundaries are:

- UTXO tenancy owns the stored wallet key, wallet-scoped transaction, address,
  and lease relations, UTXO index wire ranges, and obsolete trigger removal.
- Input normalization owns complete input rows, their wire ranges, ingestion,
  backfill, graph-reader cutover, and composition deletion.
- Spend integrity owns resolved parents, exact active spend relations, and
  late-parent enrichment.
- UTXO amount validation owns each persisted amount, not transaction totals.
- Output-set admission owns individual and checked aggregate bounds before any
  graph mutation.

## 8. References

- [Wallet Data Model and Lifecycle](../utxo_data_model.md)
- [Transaction Invalidation Flows](../tx_invalidation_flows.md)
- [Transaction store contract](../../../wallet/internal/db/interface.go)
- [PostgreSQL migrations](../../../wallet/internal/sql/pg/migrations/)
- [SQLite migrations](../../../wallet/internal/sql/sqlite/migrations/)
