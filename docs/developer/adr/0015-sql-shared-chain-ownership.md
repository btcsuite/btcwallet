# ADR 0015: Manager Lifecycle and SQL Shared-Chain Ownership

## Status

- **Status:** Accepted
- **Date:** 2026-08-13

## Relationships

- **Amends:** [ADR 0004](0004-targeted-rescan-vs-rewind.md) for SQL
  targeted-rescan ownership and [ADR 0006](0006-wtxmgr-sql-schema.md) for SQL
  block identity and canonical-frontier semantics.
- **Supersedes:** [ADR 0002](0002-controller-syncer-architecture.md).
- **Amended by:** None.
- **Superseded by:** None.

## 1. Problem

ADR 0002 gives each Wallet public lifecycle and chain-synchronization
authority. Maintained Managers need aggregate lifecycle authority. SQL Wallets
also share one Store, one canonical chain, one rollback boundary, and one chain
source. Wallet resources and historical recovery remain wallet-scoped.

## 2. Context

A SQL Manager may own zero or many durable Wallets in one SQLite or PostgreSQL
database. Canonical state, rollback, Store lifetime, and source ordering are
database-wide. Transactions, UTXOs, scan horizons, readiness, and historical
recovery are wallet-scoped.

### Constraints

- Every durable Wallet owned by a Running Manager is active.
- No accepted Wallet call or chain operation may outlive the Store.
- One waiter's cancellation cannot cancel accepted aggregate work.
- Cleanup ownership and error order are deterministic.
- Modern-kvdb remains isolated until backend retirement.

## 3. Decision

### 3.1 Manager lifecycle and active set

`Manager` is the sole public lifecycle authority. `NewManager` constructs an
Initialized Manager with terminal states:

`Initialized -> Starting -> Running -> Stopping -> Stopped`.

`Manager.Start(ctx)` fixes an ordered pointer set internally. If there are zero
Wallets, startup succeeds with an empty set. Otherwise, the set is the complete
active set in stable Wallet-ID order. Each successful caller receives a
separate caller-owned slice copy. In the Running state, no Wallet is dormant,
unloaded, restartable, or independently stoppable.

One Start outcome is fixed before publication. The first accepted terminal
cause wins:

- Publication returns the stable set.
- Owner cancellation returns its context error.
- Assembly or private-start failure returns its exact primary error.
- If Stop enters Stopping first, Start returns `ErrManagerStopped`.

A failed Start returns a nil slice. Concurrent callers share the outcome. A
waiter's cancellation ends only that waiter's wait.

After a terminal Start failure, Manager records cleanup ownership before it
releases admission. Manager then enters Stopping and reaches Stopped after
cleanup. Waiters then receive the Start result. Assembly reports its
primary error separately from cleanup outcomes. Manager records the cleanup
outcomes for Stop and never cleans those resources twice.

After a successful handoff, Manager owns the full candidate set. If the Manager
is Stopping or Stopped, Start returns a nil slice and `ErrManagerStopped`. A
reopen creates a fresh Manager.

### 3.2 Private Wallet lifecycle and call admission

Only Manager calls the private one-shot `start(ctx)` and `stop()` of each
Wallet. Wallet owns admission and drain for its public calls, workers,
cancellation, Vault, and components.

An admitted call keeps its ordinary result and drains before Store closure. A
later call returns `ErrWalletStopped` without Store access. Admission does not
serialize operation bodies.

Manager admission is separate. After Stopping begins, Manager admission returns
`ErrManagerStopped`. Manager passes no lifecycle capability into Wallet.

The final surface removes these methods, without aliases or a replacement
lookup:

- Public Wallet and Controller Start/Stop.
- Manager StartWallet, StopWallet, Load, Unload, and Close.

A retained Wallet pointer is inert after Manager Stop.

### 3.3 Create and publication

`Manager.Create(ctx, ...)` is accepted only after Create serialization and a
Running recheck. Create then does these steps:

1. Durably create the Wallet.
2. Assemble the Wallet.
3. Privately start the Wallet.
4. Publish the exact fully started pointer.

An incomplete candidate is never visible in the active set. The Wallet-set
lock protects only publication and set mutation. Durable creation, assembly,
and private startup run without the lock.

After a proven commit and start failure, Create joins the candidate. One
bounded reconciliation is allowed only when all of these conditions are true:

- An exact durable reread matches the accepted Create.
- All Store and worker results are determinate.
- One fresh candidate fully starts.

If the reconciliation succeeds, Create publishes that pointer.

A mismatch, an indeterminate state, or a fresh-start failure fixes that exact
error and enters or observes Stopping. Before Create releases serialization
and admission, Create stops and joins all unpublished candidates and attempt
resources. Cleanup errors belong to Stop. The caller then waits outside
admission. After shutdown, the caller returns its fixed error, independently
of the Stop result.

### 3.4 Live synchronization and historical recovery

Manager owns these items:

- The Store lifetime.
- The Wallet registry.
- One SQL chain source.
- Canonical frontier and reorg decisions.
- Live ordering and backpressure.
- Database-wide mutation coordination.
- The aggregate failure policy.

One coordinator delivers admitted events to the complete active-Wallet
snapshot. Wallet processors retain matching and wallet-scoped persistence.

Canonical source/frontier state, Wallet live readiness/tip, and Wallet
historical-rescan state are independent. Historical blocks do not establish
canonical membership. Historical recovery cannot move the frontier, roll back
the database, or change another Wallet.

Account import does not rescan. Address or script import registers a
live-watch obligation at the live tip. Explicit historical recovery is
Wallet-scoped and uses verified history, not the shared live stream.

Accepted live events are bounded, ordered, and never dropped for a target.
Reorg handling does these steps:

1. Stop forward admission.
2. Quiesce the affected Wallets in stable Wallet-ID order.
3. Do one database-wide rollback.
4. Reconcile the rollback.
5. Resume only from proven state.

### 3.5 Failure and shutdown ownership

- Validation, caller cancellation, and determinate request-local Store errors
  remain local.
- Recoverable source errors are retried or reconciled.
- Historical-rescan failures remain Wallet-scoped.
- Fatal Wallet invariants, indeterminate persistence, processor failures, or
  unsafe shared state stop Manager unless isolation preserves the complete
  active-set invariant.

`Manager.Stop(ctx)` does these steps:

1. Reject new Manager work.
2. Settle accepted Start and Create.
3. Freeze the Wallet set.
4. Close source admission.
5. Join the source.
6. Privately stop Wallets and drain their calls and workers.
7. Join accepted delivery and the coordinator.
8. Close Store last and once.

Wallet never closes Store.

Stop work is independent of caller contexts. A caller's cancellation ends only
that caller's wait. Later callers join the Stop work or receive the cached
result. Teardown continues after errors.

The cached aggregate orders every cleanup failure by published Wallet ID,
unpublished attempt and fixed Wallet-resource order, then source, coordinator,
and Store. Completion timing cannot change this order. Cleanup never replaces
a fixed Start or Create error. A repeated Stop returns the same aggregate.

### 3.6 Lease and scope

At most one Manager may be Starting or Running for a canonical database target
within one process. The process-local lease of that Manager lasts through all
joins and Store closure. This lease is not a global singleton or a
cross-process fence.

The lifecycle, admission, Create, failure, and shutdown contract applies to
every maintained Manager. Shared-chain coordination applies only to SQL.
Modern-kvdb follows the aggregate lifecycle, but modern-kvdb temporarily keeps
its isolated single-Wallet source path until retirement. Modern-kvdb does not
join the SQL coordinator.

These items are out of scope:

- Implementation machinery.
- Durable rescan jobs.
- Generic write locks.
- Replay state machines.
- Create manifests.
- Idle-Wallet eviction.
- Cross-process coordination.

## 4. Rationale

Only Manager spans every Wallet, the shared source and state, and Store.
Wallet-owned admission keeps call safety beside Wallet resources without
leaking Manager capability. The separation of live synchronization from
historical recovery prevents the scan of one Wallet from changing
database-wide truth.

## 5. Alternatives Considered

### Public per-Wallet lifecycle

A public per-Wallet lifecycle permits partial active sets and races aggregate
Store and source ownership.

### Manager-owned Wallet call admission

Manager-owned call admission couples Wallet safety to Manager internals. This
model also cannot prove that Wallet resources are drained.

### Combined live-sync and rescan state

A combined state lets Wallet history work affect canonical state and aggregate
failure.

### Cross-process fencing

Cross-process fencing requires a durable lease protocol beyond this
process-local contract.

## 6. Consequences

### Positive

- Lifecycle, shared state, and Store closure each have one owner.
- Running means the complete Wallet set is active.
- Wallet calls and chain work drain before Store closure.
- Historical recovery cannot mutate canonical state.

### Negative and Risks

- Start and Create settle aggregate work before returning.
- A fatal Wallet or shared-state failure can stop every Wallet.
- Slow admitted work delays Store closure.
- Other processes can still contend for the database.

## 7. Implementation Overview

Roadmap ownership is as follows:

- Task 331: terminal Manager lifecycle.
- Tasks 458 and 368: Wallet drain/private mechanics and public-surface
  removal.
- Tasks 456 and 459: runtime configuration and startup assembly.
- Task 457: the process-local lease.
- Tasks 370, 371, 372, and 423: shared delivery, frontier, rollback, and
  source cutover.
- Task 353: modern-kvdb retirement.

## 8. References

- [ADR 0001](0001-multi-wallet-architecture.md): multi-Wallet Manager scope.
- [ADR 0002](0002-controller-syncer-architecture.md): superseded lifecycle and
  per-Wallet synchronization model.
- [ADR 0004](0004-targeted-rescan-vs-rewind.md): historical scan boundaries.
- [ADR 0006](0006-wtxmgr-sql-schema.md): SQL block and frontier semantics.
