# ADR 0015: Manager Lifecycle and SQL Shared-Chain Ownership

## Status

- **Status:** Accepted
- **Date:** 2026-08-13

## Relationships

- **Amends:** [ADR 0004](0004-targeted-rescan-vs-rewind.md) for SQL
  targeted-rescan ownership and [ADR 0006](0006-wtxmgr-sql-schema.md) for SQL
  shared block identity and rollback ownership.
- **Supersedes:** [ADR 0002](0002-controller-syncer-architecture.md).
- **Amended by:** [ADR 0017](0017-manager-chain-routing.md) for
  live matching and routing ownership.
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

One runtime loop owns Manager lifecycle, active membership, delivery, rollback
and Store closure. NewManager starts that loop after construction succeeds.
Start, Stop, Create and String use typed requests and buffered replies, following the
Wallet controller pattern. Manager has no membership or shutdown mutex; its
existing atomic guard allows immediate repeated-Start rejection while the loop
is busy. Wallets, the watch registry and Store retain their own synchronization.

`Manager.Start(ctx)` fixes an ordered pointer set internally. Zero-Wallet
startup succeeds with an empty set; otherwise it is the complete active set in
stable Wallet-ID order. Each successful caller receives a separate
caller-owned slice copy. Running has no dormant, unloaded, restartable, or
independently stoppable Wallet.

Only the admitted Start assembles and publishes the complete set. Another
Start while starting, running or stopping returns `ErrStateForbidden` rather
than rebuilding Wallets or exposing a partial set.

Admitted startup failure returns a nil slice and retains its primary error.
Cleanup joins unpublished candidates and owned chain work before closing
Store, making this Manager terminal. Start after terminal cleanup returns
`ErrManagerStopped`; reopening constructs a fresh Manager.

### 3.2 Private Wallet lifecycle and call admission

Manager alone calls each Wallet's private one-shot `start(ctx, prepare)` and `stop()`.
Wallet owns admission and draining for its public calls, workers, cancellation,
Vault, and components.

An admitted call keeps its ordinary result and drains before Store closure. A
later call returns `ErrWalletStopped` without Store access. Admission does not
serialize operation bodies.

Admission transfers ownership of work, not an obligation for the caller to
keep waiting. For `ChangePassphrase`, caller cancellation ends response waiting
without canceling the accepted rotation. A caller that keeps waiting receives
the Vault's result.

Manager admission is separate and returns `ErrManagerStopped` after Stopping
begins. Manager passes no lifecycle capability into Wallet. The final surface
removes public Wallet and Controller Start/Stop plus Manager StartWallet,
StopWallet, Load, Unload, and Close, without aliases or a replacement lookup.
A retained Wallet pointer is inert after Manager Stop.

### 3.3 Create and publication

`Manager.Create` is accepted only after serialization and a Running recheck.
It durably creates, assembles, privately starts, and publishes the exact
pointer.
Startup/Create I/O completes SQL watch installation and returns its candidate
to the owner for publication. The reader retains one event through a receipt
while native queues retain later events. Matching uses the complete published
set; an incomplete candidate is never published. Delivery stays selectable
alongside lifecycle requests. The existing backend adapters supply applicable
watch preparation and failure policy.

Failed private startup terminally drains the Manager, including unpublished
candidates, before storage closes. Its primary failure is retained alongside
cleanup errors. This cutover adds no reconciliation attempt or creation retry.

### 3.4 Live synchronization and historical recovery

Manager owns Store lifetime, the Wallet registry, one notification reader,
live matching and bounded delivery, and the shared rollback barrier. Its
configured `ChainSource` is borrowed: the caller starts, connects and stops the
client. Manager owns consumption and registrations, not the connection.

Each Wallet resumes from its own committed Store checkpoint and catches up in
its existing worker. SQL Start and Create install persisted address, outpoint
and block watches before publication; they do not wait for backend currency or
historical catch-up. The membership boundary preserves events emitted during
installation without promising startup mempool backfill.

Only the next filtered block advances a checkpoint with its effects. A later
representation of a committed block can add transactions without moving that
checkpoint. Store identity checks and idempotent batches retain payload while
rejecting abandoned history; header notifications wake historical scanning.

A proven fork discovered during catch-up is offered to the Manager runtime.
The worker returns to retry so the loop can quiesce it before shared rollback.
Manager settles earlier writes, checks private hints against stored block
identity, performs the shared rollback, and resumes delivery. Native disconnects
retain the maintained height-based rollback. Manual and targeted rescans stay
Wallet-scoped and do not independently rewind the shared database.

### 3.5 Failure and shutdown ownership

- Validation, caller cancellation and determinate request-local Store errors
  remain local. Backend reads and definite mined/block failures retain retry.
- Lost required SQL watches, unexpected unmined failures and ambiguous processing
  writes cancel the SQL Manager. Definite input arbitration retains retry.
  Fresh startup restores persisted obligations.
- Required source loss or rollback persistence failure stops Manager. KVDB
  retains its single-Wallet processing and registration retry behavior.

`Manager.Stop()` sends a typed request through the same inbox as events,
recovery and I/O results. The loop records the first cleanup caller and settles
accepted Start/Create. A local worker context interrupts intake, delivery and
rollback preparation; accepted durable writes settle before closure. Join
Wallet calls/workers, the source reader and accepted I/O before closing Store
once, then cancel lifetimeCtx as the final completion signal. Stop joins that
completion; repeated calls return nil. Automatic cleanup logs errors when no
caller owns the result. Shutdown neither waits for source-channel closure nor
stops the borrowed client. Failure reports acknowledge backend policy before
cleanup joins their reporting Wallet; Wallet never closes Store itself.

Accepted passphrase rotation runs with its own cooperatively bounded context,
independent of caller and Wallet runtime cancellation. Private Wallet teardown
joins the serialized handler before locking the Vault; Store closure follows.
An operation deadline only requests cancellation. It cannot force a backend
to finish, so neither rotation completion nor shutdown has a hard time bound.

Concurrent Stop callers join cleanup. The caller that performs it receives
its cleanup errors; later Stop calls are no-ops. Start/Create failure retains
its primary error and joins unpublished candidates before storage closes.

### 3.6 Scope

Aggregate lifecycle applies to every maintained Manager. KVDB keeps one Wallet
per database and actual Store rewind, using the same reader and request ownership.
SQL Wallets share Store history and Manager-coordinated rollback, with separate
committed checkpoints and background catch-up.

Database leases, durable frontiers/rescan jobs, generic event buses, generic
write locks, create manifests, idle-Wallet eviction and cross-process fencing
are outside this cutover. No adapter, schema or Store API is required.

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

It requires a durable lease protocol outside this cutover.

## 6. Consequences

### Positive

- Lifecycle, shared state, and Store closure each have one owner.
- Running means the complete Wallet set is active.
- Wallet calls and chain work drain before Store closure.
- Wallet-scoped rescans leave sibling checkpoints unchanged.

### Negative and Risks

- Start and Create settle aggregate work before returning.
- A fatal Wallet or shared-state failure can stop every Wallet.
- Slow admitted work delays Store closure.
- Other processes can still contend for the database.

## 7. Implementation Overview

The Manager runtime owns notification routing and the shared rollback barrier.
Persisted address and output watches are reconstructed before Wallet publication.
Each Wallet resumes its committed checkpoint and catches up independently.
Shutdown cancels intake and joins the reader and Wallets before closing Store.

## 8. References

- [ADR 0001](0001-multi-wallet-architecture.md): multi-Wallet Manager scope.
- [ADR 0002](0002-controller-syncer-architecture.md): superseded lifecycle and
  per-Wallet synchronization model.
- [ADR 0004](0004-targeted-rescan-vs-rewind.md): historical scan boundaries.
- [ADR 0006](0006-wtxmgr-sql-schema.md): SQL block storage.
