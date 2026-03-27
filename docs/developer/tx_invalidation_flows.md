# Transaction Invalidation Flows

This document defines how the SQL wallet store applies invalidation-related
write workflows when one wallet event changes tx history. It complements
[Wallet Data Model and Lifecycle](./utxo_data_model.md), which defines the
stored states, and
[ADR 0006: Wallet Transaction Manager SQL Schema](./adr/0006-wtxmgr-sql-schema.md),
which defines the schema and its invariants.

It focuses on the workflow phases, the invariants each phase must preserve,
and the backend guarantees that follow from that model.

## 1. Wallet Events and Scope

From the wallet's point of view, a small set of events can change tx history:

- tx ingest, e.g. when the wallet learns about a newly created or newly
  confirmed tx.
- row-local metadata patching, e.g. when `UpdateTx` changes a label or
  block/status fields without rewriting graph edges.
- invalidation of an unmined branch, e.g. when publisher-side cleanup fails
  one local spend and its dependent descendants.
- rollback of confirmed history at a block boundary, e.g. when a reorg
  disconnects blocks and rewinds formerly confirmed wallet history.

The first two events place invalidation in the broader tx-store model. The
branch-mutating workflows described here are the ones that discover dependent
descendants, clear now-invalid spend edges, rewrite history, and commit the
whole result atomically.

## 2. Terminology

- **Root:** The first tx row directly affected by the wallet event.
- **Descendant:** An unmined tx that spends an output created by a root or by a
  later discovered descendant.
- **Branch:** One root plus every descendant discovered from that root set.
- **Spend edge:** The wallet-owned relationship that records which tx spends a
  previously created output.

## 3. Core Invariants

Every invalidation or rollback workflow must preserve the same wallet-visible
invariants.

- **Atomicity:** Each wallet event executes in one database transaction. The
  store must not commit a partially invalidated branch or a partially applied
  rollback.
- **No dangling spend edges:** If one tx becomes invalid, the store must clear
  any spend references that would otherwise keep invalid UTXO relationships
  alive.
- **Retained invalid history:** Invalid, replaced, failed, or orphaned rows
  remain part of the wallet's historical view. The workflow rewrites state; it
  does not erase audit history.
- **Event-owned graph mutation:** Row-local patching must stay row-local.
  Descendant traversal, spend-edge cleanup, replacement tracking, and rollback
  orphaning belong only to the workflows that own those mutations.
- **Event-specific root states:** Different wallet events may drive the same
  branch through different root-state outcomes. A direct conflict root may
  become `replaced`, while a descendant invalidated by that same event becomes
  `failed`.

## 4. Workflow Phases

When one branch-mutating event runs, the store follows the same overall phases.

### 4.1 Discover roots

The workflow first identifies the root rows directly affected by the wallet
event. Those roots may come from the tx being invalidated, from direct conflict
rows discovered during confirmed ingest, or from coinbase rows disconnected by
rollback.

### 4.2 Snapshot candidate txns

Before mutation starts, the workflow loads the current unmined tx set needed
for descendant discovery. This snapshot must happen first so later state
rewrites do not hide part of the branch that still needs cleanup.

### 4.3 Discover descendants

The workflow then walks the unmined candidate set to a fixed point. Each newly
discovered descendant expands the invalid parent set, which may reveal later
txns farther down the branch.

### 4.4 Clear spend edges

Before any affected row becomes visibly invalid, the workflow clears the
wallet-owned spend edges claimed by that root or descendant set. This prevents
the store from exposing rewritten rows that still appear to spend outputs from
an invalid branch.

### 4.5 Rewrite roots

After the root set is fully known and its spend edges are safe to rewrite, the
workflow applies the event-specific root outcome. The root state depends on the
wallet event, not just on the graph shape.

### 4.6 Rewrite descendants

Once the root outcome is fixed, the workflow rewrites dependent descendants to
their derived invalid state. Direct roots and descendants do not always land in
the same state, so they are handled as separate phases.

### 4.7 Commit atomically

Either every phase above commits together or none of them does. The workflow
must not leave behind half-rewritten states, partially cleared spend edges, or
only part of the affected branch updated.

## 5. Event Outcomes

The workflow phases stay the same across events, but the resulting root state
depends on which wallet event started the flow.

| Wallet event | Root outcome | Descendant outcome | Example |
| --- | --- | --- | --- |
| `InvalidateUnminedTx` | `failed` | `failed` | Publisher-side cleanup rejects one local unmined branch. |
| `CreateTx` conflict handling | direct conflict roots become `replaced` | dependent descendants become `failed` | A newly confirmed winner claims wallet-owned inputs already spent by an unmined branch. |
| `RollbackToBlock` | disconnected coinbase roots become `orphaned` | dependent descendants become `failed` | A reorg disconnects the confirming block for the root branch. |

Row-local metadata patching does not enter this branch workflow because it does
not discover descendants or rewrite spend edges.

## 6. Worked Example

Consider one branch with three txns:

- `A` is the root tx.
- `B` spends an output created by `A`.
- `C` spends an output created by `B`.

The same branch can be rewritten differently depending on the initiating event:

- Under `InvalidateUnminedTx(A)`, `A`, `B`, and `C` all become `failed`.
- Under confirmed conflict handling against `A`, `A` becomes `replaced` while
  `B` and `C` become `failed`.
- Under rollback that disconnects confirmed coinbase `A`, `A` becomes
  `orphaned` while `B` and `C` become `failed`.

In every case, descendant discovery happens before mutation and spend-edge
cleanup happens before the rewritten states become visible.

## 7. Backend Guarantees

Postgres and sqlite may differ internally in query bindings, row types, and
helper structure. They must still preserve the same workflow guarantees.

- The same wallet event yields the same final tx states.
- The same descendant branch is invalidated for the same root set.
- Spend-edge cleanup happens before invalid state becomes visible.
- The whole event remains all-or-nothing at the SQL transaction boundary.

These guarantees keep the SQL stores aligned with the legacy `kvdb` backend at
the event level, even when the SQL stores retain richer explicit invalid-
history states internally.

## 8. Relationship to Other Docs

- [`wallet/internal/db/interface.go`](../../wallet/internal/db/interface.go)
  describes the caller-facing `TxStore` contract.
- [Wallet Data Model and Lifecycle](./utxo_data_model.md) explains the
  persisted states and the "retain history" policy.
- [ADR 0006: Wallet Transaction Manager SQL Schema](./adr/0006-wtxmgr-sql-schema.md)
  defines the schema-level invariants that these workflows must preserve.
