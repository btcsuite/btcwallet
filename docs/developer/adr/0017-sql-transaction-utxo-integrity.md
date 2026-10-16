# ADR 0017: SQL Transaction and UTXO Integrity

## Status

- **Status:** Accepted
- **Date:** 2026-10-16

## Relationships

- **Amends:** [ADR 0006](./0006-wtxmgr-sql-schema.md) for transaction/UTXO
  integrity, retained history, and mutation ordering.
- **Supersedes:** None.
- **Amended by:** None.
- **Superseded by:** None.

## 1. Problem

The SQL wallet needs a behavioral integrity contract that separates a wrong
public result from a preferred storage representation. Replacing tenancy
triggers, normalizing inputs, or assigning a new graph coordinator does not,
by itself, fix a demonstrated Wallet failure. Conversely, atomic transactions
around individual writers do not alone order descendant discovery against
concurrent ingestion.

## 2. Context

This decision inspects maintained SQLite and PostgreSQL code at revision
`0f0993c138190110bd3b113a32849fac856a1f3b`. The evidence below is source
inspection and existing test coverage, not a claim that this documentation
change ran a database reproduction or implemented a correction.

This decision preserves current tenancy triggers, raw-transaction graph reads,
and exact-spend predicates. It rejects mandatory input normalization, stored
UTXO wallet keys, and optional amount CHECKs as prerequisites for behavioral
fixes or supported legacy conversion.

### Constraints

- Transactions and their effects are wallet-relative; chain ownership remains
  governed by [ADR 0015](./0015-sql-shared-chain-ownership.md).
- Graph relationships include all decoded inputs, even through non-owned
  outputs. Wallet ownership and network outpoint identity are separate facts.
- Each event commits all its transaction, credit, spend, and history effects
  together, or leaves none of those effects committed.
- Correctness is judged through maintained Wallet ingestion, `TxReader`, and
  `UtxoManager`, not unsupported direct SQL corruption.
- This ADR changes no runtime, schema, public API, replacement policy, lock,
  migration mechanism, or cross-process ownership protocol.

## 3. Decision

### Preserve satisfied invariants

**Wallet tenancy.** Both dialects derive a UTXO's wallet from its creating
transaction. The UTXO and lease migrations enforce matching address, spender,
and lease tenancy with triggers; wallet-scoped queries and inserts reinforce
that boundary. Keep those [PostgreSQL][pg-schema] and [SQLite][sqlite-schema]
protections. A hypothetical bad direct SQL write is no evidence that the
maintained Wallet needs another stored wallet key.

**Complete graph and reads.** `BuildUnminedTxRecords` and
`CollectDescendantTxIDs` decode raw inputs and walk candidate transactions to
a fixed point, including dependencies through outputs the wallet does not
own. `GetTxDetailWithOps` reconstructs owned inputs from raw previous outpoints,
so cleared spend links do not erase historical input amounts. Keep these
[shared mechanisms][common] and both dialect adapters; an input table has no
current consumer requirement.

**Exact spending outpoints.** Ingestion enumerates the decoded input position
and previous hash/output index. Both dialects' `MarkUtxoSpent` predicates match
that wallet and outpoint, require an active creating transaction, and change
only an unspent row or the identical spender/input pair. Paired-null checks
keep the two spend columns consistent. Preserve these [PostgreSQL][pg-utxos]
and [SQLite][sqlite-utxos] predicates; they already prevent ingestion from
silently assigning a different input or replacing a conflicting spender.
They do not claim to validate arbitrary edits to stored raw bytes.

**Late-parent arrival.** Both dialects' `insertCredits` calls
`markExistingChildSpends`: it decodes active raw transactions, matches credited
previous outpoints, refreshes child status, and reconciles confirmed winners
before attaching spends. Duplicate credit replay follows the same path;
batches sort known parents first. Retain this existing [PostgreSQL][pg-create]
and [SQLite][sqlite-create] behavior, including refusal of ambiguous active
spenders. Late-parent arrival does not require a new enrichment API or worker.

### Close the graph-ordering gap

**Entry points and cause.** [Wallet request handlers][controller] run
non-control operations concurrently. [Publication][publisher] records through
`CreateTx`; [synchronization][syncer] uses `ApplyTxBatch` and `ApplyScanBatch`.
All reach `CreateTxWithOps` within a SQL write transaction. Confirmed conflict
handling discovers descendants before changing root/descendant status or
spends. PostgreSQL's [write runtime][runtime] uses `BeginTx(ctx, nil)`, so its
isolation follows connection defaults; read committed does not freeze the
candidate set or lock the graph predicate.

**Concrete source-level interleaving.** Let active unmined A spend wallet coin
F, and let A create wallet output A:0. Q is an independent live wallet coin.
The following ordering is admitted under PostgreSQL read committed:

1. Confirmed winner W, learned by synchronization, spends F. Its ingestion
   inserts W and snapshots A's descendants in `collectConflictDescendants`;
   child B is absent.
2. Concurrent Wallet ingestion records B spending A:0 and Q. A is still
   active, so the exact-spend predicates admit both spends. B and its wallet
   credit commit.
3. W's writer clears A's spend of F, marks A replaced, updates only the
   descendant IDs it already collected, assigns F to W, and commits.

**Wrong public result.** `TxReader` can still report B active, and
`UtxoManager` can expose B's credit while Q remains spent by B, despite A's
replacement. Each event was atomic; the graph result is inconsistent.
Tenancy triggers and exact-spend predicates protect different invariants and
do not exclude this ordering.

**Existing backend protection.** SQLite opens connections with
`_txlock=immediate` in [NewStore][sqlite-store]. Its write transaction acquires
writer ownership before discovery, excluding the successful writer
interleaving above. Preserve that mechanism without adding a matching
application coordinator.

**Minimum ordering decision.** Participating graph writers must share an
ordering boundary from the reads deciding branch membership or parent
eligibility through their committed effects. If child ingestion wins, the
later invalidating event must include it; if the terminal transition wins,
subsequent child admission must respect that terminal parent. This is the
required observable result, not a requirement for a new graph service.

The PostgreSQL correction belongs at the existing Wallet/Store mutation
boundary and must protect the demonstrated read/mutate dependency. Its owner
must first demonstrate both orderings with barriers through maintained
behavior, then select the smallest sufficient transaction predicate, acquired
lock, or operation-specific isolation. This ADR does not choose an unproved
locking scheme or blanket serializable default. Keep unrelated Wallets
independent and include database-wide rollback in the lock-order analysis
before admitting a mechanism that could deadlock it.

Explicit PostgreSQL isolation policy follows that correction and must preserve
its proved graph guarantees. Ordinary writes may use read committed where
existing predicates and constraints suffice. A stronger graph-specific level
requires its own demonstrated need. Do not introduce repeatable-read profiles,
public tuning knobs, database-default changes, or a generic callback retry.

### Keep terminal-parent admission separate

**Entry point and existing protection.** Direct and batch ingestion share
`markInputsSpent` and `ensureWalletParentValid`. The latter uses
`HasInvalidWalletUtxoByOutpoint`, so an already-terminal parent with a
wallet-owned referenced output is rejected atomically.

**Reachable gap and wrong result.** A child learned after retained parent A
becomes terminal can reference A's non-owned output and create a wallet
credit. No UTXO row exists for that input; the owned-output guard therefore
misses A, leaving the child active and its credit visible. This is a sequential
admission gap, distinct from missing a concurrent child in a graph snapshot.

The necessary outcome is rejection before any child effect commits, using the
existing decoded parent hashes and retained parent status within the accepted
ordering boundary. Preserve owned-output rejection and deterministic replay.
Check populated live state before Wallet publication and refuse an existing
active terminal-parent branch with exact wallet, child, input and parent
diagnostics; do not silently delete it or choose a replacement status. No
input-table migration or new public admission API is needed.

### Keep output amount admission separate

**Entry point and cause.** `NewCreateTxRequest` /
`validateCreateTxParams` validate shape, status and duplicate inputs, but do not
bound every raw output and its checked sum. `Broadcast` records via
`recordTxAndCredits` before network publication, and `checkMempool` permits a
backend without precheck support. A non-owned negative output can bypass
UTXO-row checks; an over-maximum output or sum also lacks an admission guard.

**Wrong public result.** Interrupted publication or failed cleanup can leave
invalid live raw amounts/credits durable. `BuildUtxoInfo` trusts persisted
amounts on reopen. Authoring checks or a CHECK on each credited UTXO cannot
establish bounds for the complete raw output set.

The necessary outcome is individual and checked aggregate output bounds in
`0..MaxSatoshi` at the existing shared direct/batch admission boundary, before
transaction effects commit. Use the same predicate for targeted live-state
validation before exposing a populated SQL Wallet, with transaction/output
diagnostics and no partial changes. Legitimately retained terminal history
remains distinct from live credits. This correction can proceed independently
of the graph-ordering design; it requires no amount CHECK, graph redesign,
repair framework, fee/input-total policy or migration redesign.

### Preserve event-specific history and deletion

The current [invalidation workflow][invalidate] retains roots/descendants as
failed and clears their spends. Confirmed conflict ingestion retains direct
roots as replaced, descendants as failed, and direct replacement edges.
`UpdateTx` remains row-local and cannot serve as invalidation or graph repair.

Store `DeleteTx` removes only an active unmined leaf after a raw-input child
check. Public [DeleteUnconfirmedTx][writer] instead calls the existing
[branch-removal workflow][remove]: it removes an active unmined root and all
its unmined descendants, including already-terminal descendants. Both clear
spends and remove created outputs before transaction rows. Removal is an
explicit exception to retained history, not a claim of network invalidity.

[PostgreSQL][rollback] and [SQLite][sqlite-rollback] rewind/rollback detach
ordinary confirmations while orphaning
disconnected coinbases and failing their descendants atomically. Wallet rewind
preserves other wallets and shared blocks; database rollback has broader
scope. Trace those existing boundaries when proving graph ordering. The same
snapshot hazard applies to public branch removal racing ingestion, but do not
invent a public invalidation API merely because Store `InvalidateUnminedTx`
exists. Leases reserve coins and do not serialize these graph workflows.

## 4. Rationale

The existing graph representation already supports complete descendant and
history reads. Replacing it would add duplicate facts and migration work
without proving a missing public behavior. The retained ordering, parent
admission, and amount concerns each have a distinct cause and a narrow existing
boundary at which to establish their required outcome.

## 5. Alternatives Considered

### Mandatory normalized inputs or stored UTXO wallet keys

No demonstrated consumer needs another graph representation or stored tenancy
key. Existing triggers, raw reads and exact predicates remain sufficient for
those invariants; a future proposal must establish a concrete unmet need.

### One new graph coordinator or a generic write lock

Neither follows from the evidence. SQLite already excludes the interleaving;
PostgreSQL needs only the demonstrated dependency protected. Unrelated writes
and Wallets need not join a new serialization service.

### Optional amount constraints as the fix

A row constraint cannot validate uncredited outputs or their aggregate. Keep
raw-output admission independent of defensive schema hardening.

## 6. Consequences

### Positive

- Existing tenancy, raw reads, exact spends and late-parent behavior survive.
- Public-contract fixes have distinct evidence and minimal ownership bounds.
- Supported legacy facts can be validated and imported directly without an
  input normalization or graph redesign prerequisite.

### Negative and Risks

- PostgreSQL ordering still needs a barrier regression and a proved correction;
  this ADR does not claim to close it.
- Sequential non-owned terminal-parent and live-amount gaps remain separate
  implementation outcomes, including targeted populated-state validation.
- Existing event tests prove ordinary outcomes, not concurrent exclusion.

## 7. Implementation Overview

Keep the existing direct/batch admission and SQL transaction machinery.
Establish graph ordering first, preserving SQLite's immediate transactions;
then make PostgreSQL isolation explicit without weakening the proved graph
correction. Terminal-parent admission uses retained parent status under that
ordering. Raw-output admission uses the existing shared validator independently.
Legacy conversion consumes validated supported facts through these boundaries.
This decision introduces no code or schema change.

## 8. References

- [Wallet Data Model and Lifecycle](../utxo_data_model.md)
- [Transaction Invalidation Flows](../tx_invalidation_flows.md)
- [TxReader](../../../wallet/tx_reader.go) and
  [UtxoManager](../../../wallet/utxo_manager.go): public observations.
- [Existing transaction/UTXO tests][tests]:
  `TestCreateTxRejectsInvalidParentWalletOutput`,
  `TestCreateTxRejectsSecondPendingSpend`,
  `TestApplyTxBatchRejectsMismatchedWalletID`,
  `TestApplyScanBatchRejectsMismatchedWalletID`,
  `TestApplyTxBatchChildBeforeParent`, `TestApplyScanBatchChildBeforeParent`,
  `TestCreateTxReplayedCreditMarksExistingChildSpent`,
  `TestCreateTxReplayedCreditConfirmedChildReplacesUnmined`,
  `TestCreateTxConfirmedWinnerInvalidatesConflictBranch`,
  `TestGetTxDetailFindsOwnedInputAfterSpendEdgeCleared`,
  `TestRollbackToBlockFailsCoinbaseDescendants`, and
  `TestRewindWalletLeavesOtherWalletState`.
- [Invalidation coverage][invalidate-tests]:
  `TestInvalidateUnminedTxFailsBranch` includes a non-owned intermediate output.
- [Removal coverage][remove-tests]: `TestDeleteUnminedTxRemovesBranch` and
  `TestDeleteUnminedTxRemovesInvalidatedDescendant`.

[common]: ../../../wallet/internal/db/txstore_common.go
[controller]: ../../../wallet/controller.go
[publisher]: ../../../wallet/tx_publisher.go
[syncer]: ../../../wallet/syncer.go
[writer]: ../../../wallet/tx_writer.go
[runtime]: ../../../wallet/internal/db/runtime/runtime.go
[sqlite-store]: ../../../wallet/internal/db/sqlite/store.go
[pg-create]: ../../../wallet/internal/db/pg/txstore_createtx.go
[sqlite-create]: ../../../wallet/internal/db/sqlite/txstore_createtx.go
[pg-utxos]: ../../../wallet/internal/sql/pg/queries/utxos.sql
[sqlite-utxos]: ../../../wallet/internal/sql/sqlite/queries/utxos.sql
[pg-schema]: ../../../wallet/internal/sql/pg/migrations/
[sqlite-schema]: ../../../wallet/internal/sql/sqlite/migrations/
[invalidate]: ../../../wallet/internal/db/txstore_invalidateunmined_common.go
[remove]: ../../../wallet/internal/db/txstore_deleteunminedtx_common.go
[rollback]: ../../../wallet/internal/db/pg/txstore_rollback.go
[sqlite-rollback]: ../../../wallet/internal/db/sqlite/txstore_rollback.go
[tests]: ../../../wallet/internal/db/itest/txstore_utxostore_test.go
[invalidate-tests]: ../../../wallet/internal/db/itest/txstore_invalidate_edge_cases_test.go
[remove-tests]: ../../../wallet/internal/db/itest/txstore_deleteunminedtx_test.go
