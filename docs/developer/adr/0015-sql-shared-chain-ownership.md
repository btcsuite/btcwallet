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
authority. Maintained Managers need aggregate lifecycle authority, while SQL
Wallets also share one Store, canonical chain, rollback boundary, and chain
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

`Manager.Start(ctx)` fixes an ordered pointer set internally. Zero-Wallet
startup succeeds with an empty set; otherwise it is the complete active set in
stable Wallet-ID order. Each successful caller receives a separate
caller-owned slice copy. Running has no dormant, unloaded, restartable, or
independently stoppable Wallet.

One Start outcome is fixed before publication. The first accepted terminal
cause wins: publication returns the stable set; owner cancellation returns its
context error; assembly or private-start failure returns its exact primary
error; and Stop entering Stopping first returns `ErrManagerStopped`. Failed
Start returns a nil slice. Concurrent callers share the outcome, but waiter
cancellation ends only that wait.

Terminal Start failure records cleanup ownership before releasing admission,
transitions through Stopping, and reaches Stopped after cleanup. Waiters then
receive its result. Assembly reports its primary error separately from cleanup
outcomes; Manager records the latter for Stop and never cleans those resources
twice. After successful handoff, Manager owns the full candidate set. Start on
Stopping or Stopped returns a nil slice and `ErrManagerStopped`; reopening
creates a fresh Manager.

### 3.2 Private Wallet lifecycle and call admission

Manager alone calls each Wallet's private one-shot `start(ctx)` and `stop()`.
Wallet owns admission and draining for its public calls, workers, cancellation,
Vault, and components.

An admitted call keeps its ordinary result and drains before Store closure. A
later call returns `ErrWalletStopped` without Store access. Admission does not
serialize operation bodies.

Manager admission is separate and returns `ErrManagerStopped` after Stopping
begins. Manager passes no lifecycle capability into Wallet. The final surface
removes public Wallet and Controller Start/Stop plus Manager StartWallet,
StopWallet, Load, Unload, and Close, without aliases or a replacement lookup.
A retained Wallet pointer is inert after Manager Stop.

### 3.3 Create and publication

`Manager.Create(ctx, ...)` is accepted only after Create serialization and a
Running recheck. It durably creates, assembles, privately starts, and then
publishes the exact fully started pointer. An incomplete candidate is never
visible in the active set. The Wallet-set lock protects only publication and
set mutation; durable creation, assembly, and private startup run without it.

After a proven commit and start failure, Create joins the candidate. One
bounded reconciliation is allowed only when an exact durable reread matches
the accepted Create, all Store and worker results are determinate, and one
fresh candidate fully starts. Success publishes that pointer.

Mismatch, indeterminate state, or fresh-start failure fixes that exact error
and enters or observes Stopping. Create stops and joins all unpublished
candidates and attempt resources before releasing serialization and admission;
cleanup errors belong to Stop. The caller then waits outside admission and
returns its fixed error after shutdown, independently of Stop's result.

### 3.4 Live synchronization and historical recovery

Manager owns Store lifetime, the Wallet registry, one SQL chain source,
canonical frontier and reorg decisions, live ordering and backpressure,
database-wide mutation coordination, and aggregate failure policy. One
coordinator delivers admitted events to the complete active-Wallet snapshot;
Wallet processors retain matching and wallet-scoped persistence.

Canonical source/frontier state, Wallet live readiness/tip, and Wallet
historical-rescan state are independent. Historical blocks do not establish
canonical membership. Historical recovery cannot move the frontier, roll back
the database, or change another Wallet.

Account import does not rescan. Address or script import registers a live-watch
obligation at the live tip. Explicit historical recovery is Wallet-scoped and
uses verified history, not the shared live stream.

Accepted live events are bounded, ordered, and never dropped for a target.
Reorg handling stops forward admission, quiesces affected Wallets in stable
Wallet-ID order, performs one database-wide rollback, reconciles it, and
resumes only from proven state.

### 3.5 Failure and shutdown ownership

- Validation, caller cancellation, and determinate request-local Store errors
  remain local.
- Recoverable source errors are retried or reconciled.
- Historical-rescan failures remain Wallet-scoped.
- Fatal Wallet invariants, indeterminate persistence, processor failures, or
  unsafe shared state stop Manager unless isolation preserves the complete
  active-set invariant.

`Manager.Stop(ctx)` rejects new Manager work, settles accepted Start and
Create, freezes the Wallet set, closes source admission, joins the source,
privately stops Wallets and drains their calls and workers, joins accepted
delivery and the coordinator, and closes Store last and once. Wallet never
closes Store.

Stop work is independent of caller contexts. Cancellation ends only that
wait; later callers join or receive the cached result. Teardown continues
after errors.

The cached aggregate orders every cleanup failure by published Wallet ID,
unpublished attempt and fixed Wallet-resource order, then source, coordinator,
and Store. Completion timing cannot change it. Cleanup never replaces a fixed
Start or Create error, and repeated Stop returns the same aggregate.

### 3.6 Lease and scope

At most one Manager may be Starting or Running for a canonical database target
within one process. Its process-local lease lasts through all joins and Store
closure. This is not a global singleton or cross-process fence.

The lifecycle, admission, Create, failure, and shutdown contract applies to
every maintained Manager. Shared-chain coordination applies only to SQL.
Modern-kvdb follows the aggregate lifecycle but temporarily keeps its isolated
single-Wallet source path until retirement and does not join the SQL
coordinator.

Implementation machinery, durable rescan jobs, generic write locks, replay
state machines, create manifests, idle-Wallet eviction, and cross-process
coordination are out of scope.

## 4. Rationale

Only Manager spans every Wallet, the shared source and state, and Store.
Wallet-owned admission keeps call safety beside Wallet resources without
leaking Manager capability. Separating live synchronization from historical
recovery prevents one Wallet's scan from changing database-wide truth.

## 5. Alternatives Considered

### Public per-Wallet lifecycle

It permits partial active sets and races aggregate Store and source ownership.

### Manager-owned Wallet call admission

It couples Wallet safety to Manager internals and cannot prove Wallet resources
have drained.

### Combined live-sync and rescan state

It lets Wallet history work affect canonical state and aggregate failure.

### Cross-process fencing

It requires a durable lease protocol beyond this process-local contract.

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

Roadmap ownership is: Task 331, terminal Manager lifecycle; Tasks 458 and 368,
Wallet drain/private mechanics and public-surface removal; Tasks 456 and 459,
runtime configuration and startup assembly; Task 457, the process-local lease;
Tasks 370, 371, 372, and 423, shared delivery, frontier, rollback, and source
cutover; and Task 353, modern-kvdb retirement.

## 8. References

- [ADR 0001](0001-multi-wallet-architecture.md): multi-Wallet Manager scope.
- [ADR 0002](0002-controller-syncer-architecture.md): superseded lifecycle and
  per-Wallet synchronization model.
- [ADR 0004](0004-targeted-rescan-vs-rewind.md): historical scan boundaries.
- [ADR 0006](0006-wtxmgr-sql-schema.md): SQL block and frontier semantics.
