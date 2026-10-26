# ADR 0017: Manager Chain Routing

## Status

- **Status:** Proposed
- **Date:** 2026-10-26

## Relationships

- **Amends:** [ADR 0015](0015-sql-shared-chain-ownership.md), section 3.4's
  assignment of live transaction matching to Wallet processors.
- **Supersedes:** None.
- **Amended by:** None.
- **Superseded by:** None.

## 1. Problem

Several SQL Wallets share one backend notification stream. Independent readers
compete for events instead of each receiving its relevant transactions and
block progress. Forwarding every transaction to every Wallet repeats parsing
and relevance work. Manager needs enough information to select recipients
before their independently scheduled workers persist the transactions.

## 2. Context

Manager already owns aggregate lifecycle, the Wallet registry, shared SQL
storage, and the caller-provided chain source. Wallet owns its existing worker,
transaction persistence, synchronization status, catch-up, and explicit scans.

Wallets already declare address and outpoint interests during address delivery,
publication, synchronization initialization, and committed-scan refresh. Stored
addresses and ListOutputsToWatch reconstruct those interests, including outputs
spent by unmined transactions. These mechanisms can supply routing ownership
without live-event Store reads or another recovery cache.

### Constraints

- Preserve asynchronous Wallet initialization, retry, and backend ordering.
- Install routing ownership before a successful native subscription can emit.
- A watched address or outpoint can belong to several Wallets.
- Preserve source order and bounded, lossless admission for each live target.
- Give every maintained Manager the same reader ownership; kvdb retains
  one Wallet per database and its existing address allocation behavior.
- Preserve native backend semantics rather than inventing uniform SPV mempool
  or subscription guarantees.

## 3. Decision

Manager owns a private chainSyncer through a private behavior interface: one
backend reader, a synchronized additive watch registry, and matching of live
transactions to Wallet IDs. Manager owns the reader's lifetime context,
cancellation and join. Wallet owns its independent lifetime and chain processor:
its existing worker applies relevant events and performs catch-up and explicit
recovery. No new public API is needed.

A Wallet registration identifies its Wallet ID and addresses or outpoints.
Manager records the association before calling the existing backend method,
without holding routing locks during I/O. Success means that native method
succeeded. Failure remains with the existing caller or processor retry; an
already recorded association never suppresses a retry. The registry indexes
each address or outpoint to its set of Wallet owners, allowing direct event
lookups and shared interests without scanning each Wallet. Its short mutex
protects the mutable sets; parsing, native I/O and delivery happen outside it.

Manager parses transaction output addresses once and unions recipients from
matching outputs and watched inputs. Input script addresses also match before
recovery learns their funding outpoints; they remain separate from output
credit metadata. A transaction reaches each interested Wallet once. Matching
outputs become watched outpoints before the next record or event is matched,
so a queued parent's spend remains routable before the
parent commits. Learned interests remain additive for replacement spends.
Store still determines account and credit ownership transactionally.

Events carry immutable prepared matches and original notification metadata.
Each Wallet has a capacity-one mailbox feeding its existing worker. An actual
filtered block reaches every current Wallet, including those with no matching
transactions. Header-only block notifications retain their wakeup meaning:
catch-up scans recovery-window addresses before advancing the checkpoint.
Disconnect and control events use ordinary Wallet handlers.

Manager snapshots membership under its existing registry lock, releases it,
then routes and sends in source order. Create joins subsequent snapshots after
ordinary publication. There is no readiness handoff, acknowledgment, startup
barrier, pause/resume protocol, or extra per-Wallet worker.

Manager's reader lifetime is separate from each Wallet's synchronization and
recovery state. Start and Create do not promise completed watch installation
or aligned tips. No-gap registration covers future admitted events after a
successful subscription; it does not promise startup mempool backfill.

Ordinary processing and registration failures retain Wallet retry behavior.
Loss of the required notification stream terminates the reader and stops
Manager. Shutdown cancels delivery, drains Wallet calls and workers, and closes
Store under the admission lock. It releases that lock before joining the
reader, which can be waiting for a membership snapshot. This order is safe
because the reader only routes in-memory events; every Store user has already
joined. Failed startup and creation also join before returning. The borrowed
backend client remains caller-owned.

## 4. Rationale

Watch declarations already identify the Wallet that owns an interest. Recording
that identity before native activation avoids a registration gap without
querying an incompletely updated Store for every event. Learning outputs during
matching also handles parents that have only been admitted to a Wallet queue.

Existing Wallet workers preserve processing order and persistence boundaries.
A bounded mailbox keeps admission asynchronous without adding an unbounded
queue, dispatcher worker, or processing-completion coordinator.

## 5. Alternatives Considered

### Independent SQL backend readers

Competing receives cannot broadcast a single channel to multiple Wallets.

### Broadcast all transactions and match in each Wallet

This retains repeated parsing and per-Wallet relevance work on the live path.

### Caller-fed fanout with Wallet filtering (#1434)

[PR #1434](https://github.com/btcsuite/btcwallet/pull/1434) accepts ordered events
from a caller and forwards them to Wallet workers, which select relevant
transactions. The caller must own source consumption and delivery, and each
Wallet repeats relevance/filtering work. Manager-owned consumption and recorded
watch declarations put those responsibilities together and let Manager prepare
transactions once before selecting recipients. Wallet workers retain their
persistence and recovery responsibilities.

### Query Store for recipients at delivery

A parent can still be queued when its child arrives. Durable ownership alone
cannot identify that child's recipient until the parent commits.

### Independent unbounded recipient queues

They hide a slow Wallet by growing memory and require additional lifecycle and
scheduling policy. Bounded backpressure is sufficient for the current contract.

## 6. Consequences

### Positive

- Manager consumes the shared stream once and owns live relevance decisions.
- Wallet synchronization and recovery remain independently scheduled.
- Existing native subscription, Store batch, and Wallet retry paths are reused.
- Pending-parent spends remain routable without persistence-completion waits.

### Negative and Risks

- A slow live Wallet can fill its mailbox and backpressure the shared reader,
  including while scanning or waiting for retry. Independent state does not
  imply unlimited independent throughput.
- Additive interests retain memory for the Manager lifetime. Deleting an
  outpoint on its first spend loses replacement and reorg-spend routing, and
  addresses can receive again. Any bounded retirement policy needs a separate
  decision; this design defines no GC threshold or background worker.
- A dead required source stops every Wallet served by that Manager.
- Shared rollback coordination and historical-write safety remain separate
  follow-up work. This routing change retains existing checkRollback and
  historical Store boundaries; it does not claim the full coordination design
  in ADR 0015 or add a frontier, fencing, or reconciliation protocol.

## 7. Implementation Overview

Every Manager supplies one private chainSyncer to its Wallets.
Wallet watch producers delegate to it; their existing processors consume
prepared events. Btcd and bitcoind keep their current address/outpoint/block
subscriptions. Neutrino keeps birthday initialization, historical address
registration, and no-op spent subscription. Kvdb delegates its native address
registration through the same owner and retains its one-Wallet storage limit.

Unit coverage checks registration order, shared recipients, unknown-prevout
input-address spends, queued-parent spends, progress, ordered admission,
membership changes and joined shutdown.
Native integration coverage funds two Wallets and confirms a payment from one
to the other, then checks their respective transaction and coin views on full
nodes and Neutrino. Existing confirmed-watch replay covers persisted SPV
interests. No schema, generated output, backend adapter, or Store implementation
changes are needed.

## 8. References

- [ADR 0015](0015-sql-shared-chain-ownership.md): aggregate lifecycle and the
  broader shared-chain coordination design.
- [ADR 0004](0004-targeted-rescan-vs-rewind.md): Wallet historical recovery.
- [ADR 0005](0005-no-auto-rescan-on-import.md): explicit recovery after import.
- [Scanning and synchronization](../scanning_sync_architecture.md): existing
  catch-up and recovery mechanisms.
