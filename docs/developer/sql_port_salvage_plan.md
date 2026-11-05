# SQL Port Salvage Plan

Status: proposed

Date: 2026-07-10

Scope: `btcwallet` SQL project, beginning with issue
[#1015](https://github.com/btcsuite/btcwallet/issues/1015)

## Decision

We should split the current project into two projects and finish them in order:

1. Port the existing wallet to SQLite and PostgreSQL while preserving its
   public API, lifecycle, synchronization flow, signing behavior, and `lnd`
   integration.
2. Revisit role-based interfaces, the controller/syncer rewrite, the key vault,
   and the other architectural work after the SQL wallet has shipped and has
   migration plus end-to-end coverage.

The current `interface-wallet` and `sql-wallet` branches should remain as
read-only source branches. We should not merge either umbrella PR. We should
create a new port-first branch from `master`, transplant the reusable work in
reviewable units, and keep an explicit mapping from every old commit and PR to
its new destination or deferral reason.

This is a salvage, not a restart. Most of the schema, SQL queries, generated
code, backend implementations, data conversion helpers, and backend tests can
be reused. The public interface and runtime rewrites are a separate project.

## What Happened

The project began with three related but distinct ideas:

- [PR #1026](https://github.com/btcsuite/btcwallet/pull/1026) put the existing
  wallet behind a minimal `wallet.Interface` for `lnd`. The matching `lnd`
  integration was a small mechanical change in
  [lnd PR #10136](https://github.com/lightningnetwork/lnd/pull/10136).
- [Issue #1015](https://github.com/btcsuite/btcwallet/issues/1015) proposed a
  backend-neutral store, a KV adapter, SQL implementations, integration tests,
  and finally a KV-to-SQL migration tool.
- [Issue #1038](https://github.com/btcsuite/btcwallet/issues/1038) separately
  proposed role-based wallet interfaces, an actor-style controller, and new
  account, address, UTXO, transaction, PSBT, and signing APIs.

Those projects were then stacked together. The SQL work was based on the
interface rewrite, so the persistence port inherited a new public API and a new
runtime before either had been integrated into `lnd`.

This coupling was not only accidental late drift. Issue #1015 made #1038 its
completed interface workstream, and the database design in
[issue #1080](https://github.com/btcsuite/btcwallet/issues/1080) deliberately
favored task-specific business operations in the store. The problem is the
missing cut line: interface, runtime, storage, and signing redesigns all became
prerequisites for shipping any SQL backend.

The original storage boundary was clear. In the discussion on issue #1015,
the [intended rule](https://github.com/btcsuite/btcwallet/issues/1015#issuecomment-3192792132)
was that changes to sqlc and internal database types did not require changes to
external API types. Review on
[PR #1065](https://github.com/btcsuite/btcwallet/pull/1065#discussion_r2373671304)
already described the public interface and mid-level store as two breaking
points. [PR #1111](https://github.com/btcsuite/btcwallet/pull/1111#discussion_r2509873087)
then made that coupling concrete by moving away from mapping KV data toward a
generalized database API, while a later comment noted that the API could change
again with the controller refactor.

### Umbrella branches

| Layer | PR | Tip | Commits beyond base | Diff |
| --- | --- | --- | ---: | ---: |
| `master` to `interface-wallet` | [#1083](https://github.com/btcsuite/btcwallet/pull/1083) | [`78ac6aeb`](https://github.com/btcsuite/btcwallet/commit/78ac6aeb02d27592ae40c2b2c71d887a6089de4f) | 309 | 115 files, +56,994/-10,995 |
| `interface-wallet` to `sql-wallet` | [#1110](https://github.com/btcsuite/btcwallet/pull/1110) | [`7e1ac757`](https://github.com/btcsuite/btcwallet/commit/7e1ac7570d099e8985aec00d77ee3383c0a1cadb) | 660 | 478 files, +110,707/-9,264 |
| `master` to `sql-wallet` | combined | same tip | 969 | 536 files, +159,268/-11,826 |

Both umbrella PR bodies still say that they exist to track rebase conflicts
and contain no usable description of the final design. PR #1083 has no inline
review threads; its only human approval has the body `.`. PR #1110 has no human
review. The individual feeder PRs contain the real design and review history.

Repository metadata shows 39 PRs targeting `interface-wallet`, 103 targeting
`sql-wallet`, and another nine stacked between feeder branches. Some were
superseded or closed without merge, but this gives the scale of the branch
ecosystem we need to account for.

### How the scope grew

| Wave | Representative PRs | What landed |
| --- | --- | --- |
| Public role interfaces | [#1050](https://github.com/btcsuite/btcwallet/pull/1050), [#1052](https://github.com/btcsuite/btcwallet/pull/1052), [#1059](https://github.com/btcsuite/btcwallet/pull/1059), [#1076](https://github.com/btcsuite/btcwallet/pull/1076), [#1091](https://github.com/btcsuite/btcwallet/pull/1091), [#1092](https://github.com/btcsuite/btcwallet/pull/1092), [#1128](https://github.com/btcsuite/btcwallet/pull/1128) | New account, address, UTXO, transaction, signer, and PSBT contracts; old methods renamed to `*Deprecated`. |
| Lifecycle rewrite | [#1137](https://github.com/btcsuite/btcwallet/pull/1137), [#1144](https://github.com/btcsuite/btcwallet/pull/1144), [#1148](https://github.com/btcsuite/btcwallet/pull/1148), [#1155](https://github.com/btcsuite/btcwallet/pull/1155), [#1156](https://github.com/btcsuite/btcwallet/pull/1156), [#1157](https://github.com/btcsuite/btcwallet/pull/1157), [#1161](https://github.com/btcsuite/btcwallet/pull/1161) | `Controller`, `Manager`, state machine, new syncer, retry loop, and replacement of loader/start/stop/rescan flow. |
| SQL foundation | [#1065](https://github.com/btcsuite/btcwallet/pull/1065), [#1111](https://github.com/btcsuite/btcwallet/pull/1111), [#1125](https://github.com/btcsuite/btcwallet/pull/1125), [#1134](https://github.com/btcsuite/btcwallet/pull/1134), [#1142](https://github.com/btcsuite/btcwallet/pull/1142), [#1147](https://github.com/btcsuite/btcwallet/pull/1147), [#1162](https://github.com/btcsuite/btcwallet/pull/1162), [#1185](https://github.com/btcsuite/btcwallet/pull/1185) | sqlc, schema migrations, SQLite/PostgreSQL stores, wallet/account/address/transaction/UTXO models. |
| Store semantic engine | [#1168](https://github.com/btcsuite/btcwallet/pull/1168), [#1186](https://github.com/btcsuite/btcwallet/pull/1186), [#1187](https://github.com/btcsuite/btcwallet/pull/1187), [#1193](https://github.com/btcsuite/btcwallet/pull/1193), [#1196](https://github.com/btcsuite/btcwallet/pull/1196), [#1209](https://github.com/btcsuite/btcwallet/pull/1209) | A generalized store, KV implementation, backend conformance helpers, replacement/invalidation, pagination, and error mapping. |
| Wallet routing rewrite | [#1201](https://github.com/btcsuite/btcwallet/pull/1201), [#1202](https://github.com/btcsuite/btcwallet/pull/1202), [#1214](https://github.com/btcsuite/btcwallet/pull/1214), [#1230](https://github.com/btcsuite/btcwallet/pull/1230), [#1238](https://github.com/btcsuite/btcwallet/pull/1238), [#1243](https://github.com/btcsuite/btcwallet/pull/1243), [#1248](https://github.com/btcsuite/btcwallet/pull/1248) | Existing wallet methods were rewritten around the generalized store and the new role interfaces. |
| Runtime and scan rewrite | [#1256](https://github.com/btcsuite/btcwallet/pull/1256), [#1257](https://github.com/btcsuite/btcwallet/pull/1257), [#1258](https://github.com/btcsuite/btcwallet/pull/1258), [#1270](https://github.com/btcsuite/btcwallet/pull/1270), [#1271](https://github.com/btcsuite/btcwallet/pull/1271) | Startup, sync tips, rewind, scan writes, targeted rescan identity, and a Store-mandatory syncer. This tail is still open. |
| Secret and signer redesign | [#1166](https://github.com/btcsuite/btcwallet/pull/1166), [#1170](https://github.com/btcsuite/btcwallet/pull/1170), [#1171](https://github.com/btcsuite/btcwallet/pull/1171), [#1265](https://github.com/btcsuite/btcwallet/pull/1265), [#1272](https://github.com/btcsuite/btcwallet/pull/1272), [#1273](https://github.com/btcsuite/btcwallet/pull/1273), [#1279](https://github.com/btcsuite/btcwallet/pull/1279) | New encryption ADRs, account-secret routing, key-vault lifecycle, and a new sealed signing request/locator model. PRs #1272 and #1279 remain open; the signing wallet adapter is incomplete. |

The SQL-only part is no longer most of the change. A path-based count of
`wallet/internal/sql/**` plus `wallet/internal/db/{pg,sqlite}/**` accounts for
34,349 of 110,707 added lines between `interface-wallet` and `sql-wallet`. This
includes generated code and excludes common database interfaces and converters.
The rest is the common semantic engine, KV adapter, wallet routing, tests,
tooling, and documentation.

## Current Integration State

The green SQL checks do not mean that an SQL-backed wallet works end to end.

- There are ten schema revisions for each of SQLite and PostgreSQL: blocks,
  wallets, address types, key scopes, accounts, addresses, transactions, UTXOs,
  replacements, and leases.
- The database integration tests exercise the store implementations.
- `bwtest/database.go` still supports only `kvdb` when opening a wallet database.
  Its SQLite/PostgreSQL path is a TODO.
- `wallet/manager.go` still constructs `kvdb.NewStore(...)` unconditionally and
  hard-codes wallet ID zero.
- Chain end-to-end CI runs with `db=kvdb`. The SQLite/PostgreSQL jobs run the
  store test suite, not a wallet create/start/sync/fund/sign/spend flow.
- The only wallet-level manager case creates a wallet. It cannot select an SQL
  runtime through the current harness.
- The project has schema migrations, but no importer from an existing
  `wallet.db`. The migration described in ADR 0001 is still future work.

PR #1110 is currently `UNSTABLE`, not fully green. In run `29069861156`, the
format, unit, SQLite, PostgreSQL, and chain integration jobs passed, while the
`Check commits` job `86289006951` failed. More importantly, none of those green
jobs establishes an SQL-backed wallet runtime.

The runtime rewrite has also produced the kind of review surface we should not
combine with a storage port. Review on PR #1258 found stale dual sync tips,
loss of transaction dependency ordering during rebroadcast, wallet-global
rollback behavior, an ownership race, a bare-multisig ownership regression,
and changed pending-transaction rebroadcast semantics. Several findings were
subsequently addressed, but they show how hard it is to distinguish storage
regressions from new runtime behavior in the current stack.

## `lnd` Compatibility Audit

Current `lnd` master pins btcwallet v0.18.0 and stores a
`wallet.Interface` in `lnwallet/btcwallet.BtcWallet`. It directly calls the
existing btcwallet lifecycle, account, address, lease, signer, and PSBT methods.

The interface branch grows `*wallet.Wallet` from 92 to 145 exported methods.
Twenty-one existing concrete method contracts change in a type-significant
way. The 59-method `wallet.Interface` renames 18 existing methods to
`*Deprecated` while using the old names for new signatures. Of those changes,
`lnd` directly relies on at least these sixteen old contracts:

`Start`, `Stop`, `Unlock`, `NewAddress`, `AddressInfo`, `ImportAccount`,
`ImportPublicKey`, `ImportTaprootScript`, `ListUnspent`, `LeaseOutput`,
`ReleaseOutput`, `ListLeasedOutputs`, `FundPsbt`, `FinalizePsbt`,
`DecorateInputs`, and `ScriptForOutput`.

The PSBT changes are not mechanical:

- `FundPsbt` replaces the existing argument contract and control path with
  `FundPsbt(context.Context, *FundIntent) (*psbt.Packet, int32, error)`. The new
  path still mutates the intent's packet, but also returns the packet.
- `DecorateInputs` gains a context and returns a packet.
- `FinalizePsbt` drops the key scope and account parameters.
- The new funding policy has no direct replacement for `lnd`'s arbitrary
  `WithUtxoFilter` callback.
- The new implementation changes coin-selection, state-validation, sorting,
  derivation, and finalization ownership at the same time as data access.
- `lnd` retains signing logic for Lightning-specific input tweaks, while the
  new btcwallet signer and key-vault APIs move that ownership again.

This compile audit used the unmodified local `lnd` checkout at
`31168557c3a8602d7669c1eb86eddd07d9892bc6` and the SQL tip
`7e1ac7570d099e8985aec00d77ee3383c0a1cadb`. The test command used a temporary
modfile with explicit local replacements, then ran
`go test -mod=mod -modfile=<tmp.mod> ./lnwallet/btcwallet`.

That build fails before reaching the direct wallet calls.
The first compile error is `waddrmgr.Manager.FetchScopedKeyManager` returning
`waddrmgr.AccountStore` where `lnd` needs a concrete
`*waddrmgr.ScopedKeyManager`. `(*wallet.Wallet).AddScopeManager` has the same
concrete-to-interface return change and fails later when `lnd` passes the result
to `InitAccounts`. Once those are bypassed diagnostically, the old wallet
methods above are missing from `wallet.Interface`, and
`PsbtPrevOutputFetcher` has changed from one result to two.

The port-first branch must compile with unmodified `lnd`. An `lnd` adaptation
PR is not an acceptable prerequisite for the storage port.

## Salvage Boundary

### Reuse now

We should transplant these parts onto a fresh branch based on `master`:

- sqlc configuration, unified dialect tooling, generated-code checks, and the
  SQLite/PostgreSQL connection and retry scaffolding;
- the schema revisions, after a schema review against current KV semantics;
- SQL queries and generated code for wallet metadata, scopes, accounts,
  addresses, transaction incidences, inputs, credits, and leases;
- SQLite and PostgreSQL store implementations;
- backend-neutral data conversion helpers that do not leak into public APIs;
- transaction conflict removal, rollback, and lease tests that encode existing
  wallet behavior;
- store-level SQLite/PostgreSQL integration tests and useful cross-backend
  conformance vectors;
- focused fixes discovered during review, such as error normalization,
  uniqueness constraints, transaction detail reads, and deterministic rollback.

The store may remain a new internal interface. The constraint is that it serves
the existing wallet, not that the wallet and its consumers adopt a new public
interface.

### Rework behind the old facade

These changes contain useful SQL logic, but their wallet-facing portions must
be rewritten around the current API and control flow:

- transaction and UTXO reads/writes;
- address and account persistence;
- output leases;
- PSBT data lookup and derivation;
- scan batch persistence and rollback;
- wallet metadata and backend construction.

For example, the useful part of PR #1255 is its store-backed UTXO, parent
transaction, and derivation lookup. We should retain that data access while
keeping the existing `FundPsbt`, `DecorateInputs`, and `FinalizePsbt`
signatures and semantics.

### Defer intact

The following work should move to a post-port roadmap. It should not be deleted
or silently abandoned:

- role-based public interfaces and all `*Deprecated` renames;
- `Controller`, `Manager`, the orthogonal state machine, and the new syncer;
- replacement of `Loader`, `Start`, `Stop`, `SynchronizeRPC`, chain
  notifications, rescan, and recovery control flow;
- new public account, address, UTXO, transaction, PSBT, and signing models;
- the key-vault and single-passphrase encryption redesign;
- actor-model concurrency changes;
- public pagination and unit-type redesigns;
- generalized test-mock and benchmark reorganizations that are not needed to
  prove SQL parity.

Deferral means retaining the original branches, PRs, reviews, and commit
mapping. After the port ships, each item can be rebased on the smaller system
and judged on its own merits.

## Compatibility Contract

The port-first train has the following non-negotiable constraints:

1. The exported `wallet.Interface` method set and signatures remain unchanged.
2. Existing concrete `*wallet.Wallet`, `waddrmgr`, `wtxmgr`, and loader methods
   used by `lnd` remain source compatible.
3. The KV backend remains behaviorally unchanged while SQL is opt-in.
4. The current startup, shutdown, synchronization, notification, rescan,
   recovery, coin-selection, signing, and PSBT control flows remain in place.
5. SQL types stay inside the SQL/store packages. No sqlc type crosses a wallet
   or consumer boundary.
6. Existing errors, ordering, locking, account/scope selection, watch-only
   behavior, and transaction replacement semantics remain observable at the
   wallet API.
7. Backend selection is additive. Existing `lnd` configuration continues to
   start a KV wallet without code changes.
8. KV removal is out of scope until migration has shipped, rollback has been
   exercised, and SQL has survived at least one release cycle.
9. `Database()` and caller-owned walletdb namespaces retain their current
   semantics. SQL stores btcwallet-owned state; it does not silently absorb or
   discard `lnd` and application buckets.
10. Separate Go modules such as `wtxmgr`, `walletdb`, `wallet/txauthor`,
    `wallet/txrules`, and `wallet/txsizes` keep compatible released APIs unless
    the port explicitly versions and tests the full module set together.

Any PR that needs to break one of these constraints belongs in the later
refactor project.

## Contribution and History Preservation

We should preserve contribution history as a first-class deliverable.

1. Tag or otherwise pin the exact `interface-wallet` and `sql-wallet` tips
   before starting the salvage train.
2. Generate `docs/developer/sql_port_inventory/commit_map.csv` with one row per
   source commit: source SHA, introducing feeder PR, related PRs, author,
   category, disposition, destination PR, destination SHA, and notes. The 151
   feeder PRs overlap heavily, so aggregate/base PRs must not double-attribute
   a commit.
3. Cherry-pick a source commit unchanged when it applies cleanly and belongs
   wholly in the port.
4. When a source commit mixes reusable storage code with deferred refactoring,
   reconstruct the storage portion with the original author where one author
   owns the retained work. Record every source SHA in the commit body with an
   `Extracted-from:` line.
5. When retained code materially combines work from several people, keep the
   primary author and add real contributor `Co-authored-by` trailers. Never add
   tool attribution.
6. Do not squash the salvage train into one commit. Keep commits reviewable by
   subsystem and preserve original authorship wherever the code boundary
   permits.
7. Before closing an old feeder PR, post its destination PR and commit-map rows.
   A contributor should be able to follow their work from the old stack to the
   final branch.
8. Use `git range-diff`, source/destination patch IDs, and the commit map in the
   final audit. Every old commit must be marked `picked`, `extracted`,
   `deferred`, `superseded`, or `dropped` with a reason.

This gives us a defensible answer to both questions: which existing work was
used, and where did each contributor's work go?

## Port-First PR Train

Each stage is independently mergeable. A later stage cannot be used to justify
merging an earlier stage with a known compatibility or parity gap.

### Stage 0: Freeze and inventory

- Pin both umbrella tips and every open feeder head.
- Create the commit map and classify all 969 commits.
- Mark each feeder PR as SQL foundation, reusable semantic fix, wallet routing,
  public refactor, runtime rewrite, key-vault/signing rewrite, test/tooling, or
  superseded work.
- Record the exact current exported API and a list of btcwallet symbols used by
  `lnd`.

Exit gate: every source commit and all 151 non-master PRs in the branch
ecosystem, plus the master-based umbrella PR #1083, have a recorded disposition.
No code has been discarded by omission.

### Stage 1: SQL build and schema foundation

- Transplant sqlc/tooling support and connection scaffolding.
- Keep the Stage 1 database helpers internal and based on `database/sql` plus
  `golang-migrate`. We evaluated `github.com/lightningnetwork/lnd/sqldb/v2`,
  which contains useful connection and migration utilities, but it has no
  tagged release at the frozen lnd revision and its module-level dependency
  replacements aren't inherited by btcwallet. Its public migration surface
  also doesn't expose the down or target-version operations required by this
  stage's rollback gate. The older `lnd/kvdb/sqlbase` package is a v1 KV
  compatibility facade, so adopting it would couple the port to the abstraction
  that v2 intentionally replaces. Revisit v2 after the port, once it has a
  stable release and the required migration controls.
- Transplant the SQLite and PostgreSQL schemas and generated queries.
- Review constraints and indexes against KV behavior, especially account
  identity, imported addresses, watch-only state, transaction conflicts,
  duplicate mined incidences, credit ownership, and lease expiry. Defer the
  rewrite-only replacement-history table because current `wtxmgr` physically
  removes conflicts and cannot populate that audit trail.
- Change the salvaged secret schema to preserve the existing dual
  public/private passphrase hierarchy and encrypted blobs. The current SQL ADRs
  introduce a single-passphrase hierarchy, XChaCha re-encryption, and different
  treatment of public metadata. Those choices belong to the deferred key-vault
  project. If legacy ciphertext cannot be represented without re-encryption,
  stop here and make that a separate architectural decision.
- Persist the legacy sticky address-used bit. The current SQL design derives
  usage from surviving UTXOs, which cannot represent an old address marked used
  after its relevant history has disappeared. The port-first schema must
  preserve `LastUnusedAddress` and gap-limit behavior directly.
- Keep SQL packages internal.

Exit gate: generated code is reproducible; both databases migrate from empty to
head and back; no wallet or `lnd` API changes.

### Stage 2: Internal store implementations

- Introduce the minimum internal store contract needed by the existing wallet.
- Transplant SQLite/PostgreSQL implementations one domain at a time: metadata,
  accounts/scopes, addresses/secrets, transaction incidences, inputs, credits,
  and leases.
- Retain backend conformance cases, but define expected behavior from current
  KV wallet tests and public behavior rather than from the rewritten wallet.
- Do not make the KV wallet route through the new store just to prove the
  abstraction. A test adapter may reuse KV readers, but the production KV path
  stays untouched during this stage.

Exit gate: SQLite and PostgreSQL pass the same domain vectors, including error,
ordering, rollback, and restart cases.

### Stage 3: Existing wallet on SQL

- Add an internal backend selector and a persistence dependency alongside the
  current loader, address manager, and transaction store. The KV path continues
  through its existing `walletdb` objects. The SQL path must not emulate the
  `walletdb.ReadWriteBucket` API.
- Construct an SQL store without introducing `Controller` or the new `Manager`.
- Keep the caller-provided `walletdb.DB` for `Database()` and caller-owned
  namespaces. In `lnd`, btcwallet SQL state and `lnd` application metadata are
  separate persistence domains.
- Route existing wallet operations behind their current methods, one subsystem
  per PR.
- Keep `Start`, `Stop`, `SynchronizeRPC`, chain notifications, rescan, recovery,
  and the current locking model.
- Keep PSBT/signing signatures and algorithms. Replace only their persistent
  reads and writes.

Suggested routing order:

1. wallet metadata plus create/load;
2. accounts, scopes, and addresses;
3. transaction reads and labels;
4. UTXOs and leases;
5. transaction writes, conflict removal, and rollback;
6. PSBT lookup and signing data;
7. scan state, restart, and recovery persistence.

Exit gate: a wallet can create, load, start, sync, derive, fund, sign, publish,
restart, rescan, reorg, and recover on all three backends through the existing
API.

The lifecycle test must include `lnd`'s actual order: unlock, create scopes and
call `InitAccounts`, start the chain backend, start the wallet, then call
`SynchronizeRPC`. Source-compatible method names are insufficient if SQL changes
those ordering assumptions.

### Stage 4: KV-to-SQL migration

Build an offline, copy-based importer. It must never mutate the source
`wallet.db`.

The importer should:

- copy the KV file, leave the original read-only, and run existing
  `waddrmgr`/`wtxmgr` upgrades on the disposable copy before reading the current
  KV shape. Preflight must identify upgrades that need a seed, callback, or
  private passphrase;
- create a new SQL target marked `incomplete`;
- preflight wallet versions, network, passphrase state, and target emptiness;
- import wallet metadata, birthday and sync state, scopes, accounts, next
  derivation indexes, imported keys/scripts, address usage, transaction labels,
  observable mined/unmined state, credits, and leases;
- copy only btcwallet-owned namespaces from an externally supplied walletdb;
  leave `lnd` and other application buckets untouched;
- preserve encrypted secret material and the existing encryption model rather
  than combining migration with the key-vault redesign;
- commit resumable stages while keeping the target unavailable, then atomically
  mark it complete after final verification. Retry must resume or safely remove
  an incomplete target;
- produce a deterministic report of row counts and canonical semantic digests.
  Digests use stable logical keys and ordering, exclude backend IDs and generated
  timestamps, and verify decrypted key equivalence separately from randomized
  ciphertext;
- reopen the SQL wallet, derive look-ahead addresses, and verify ownership,
  balances, transaction state, and sync tip;
- leave the KV file and a clear rollback instruction in place.

The importer can map only state observable in the source. KV may already have
deleted conflicting transactions and descendants, so migration cannot recreate
a complete SQL replacement graph. Define a canonical mapping for surviving
mined/unmined transactions plus credits/debits, and do not invent lost history.

Lease migration uses a recorded snapshot time. Leases expired by import time
are dropped; retained leases preserve lock ID, outpoint, and absolute expiry,
and are checked again when the wallet reopens.

Migration fixtures must cover several historical wallet versions, watch-only
wallets, imported accounts, imported taproot scripts, custom `lnd` key scopes,
unconfirmed transaction conflicts, leases, partially synced wallets, and
wallets requiring rescan.

Exit gate: migration is repeatable and failure-atomic; the migrated wallet
matches a canonical KV snapshot before and after restart plus rescan.

### Stage 5: `lnd` integration and rollout

- From Stage 0 onward, compile unmodified `lnd` against each candidate tip with
  replacements for the btcwallet root and every intentionally changed leaf
  module. Dependency-module `replace` directives do not apply when `lnd` is the
  main module, so a root-only replacement is not enough. Prefer avoiding leaf
  module changes; otherwise publish and test a compatible version set before
  integration.
- Add an opt-in SQL backend to `lnd` without changing its wallet or signer
  interfaces.
- Keep `lnd`'s shared KV database for application metadata and the
  `lnwallet/walletReady` marker. Define create, crash-recovery, unload, backup,
  and migration ordering across the KV metadata database and btcwallet SQL
  database. Since there is no atomic transaction across them, an SQL wallet
  created before `walletReady` must be detectable and resumable or removable.
- Run btcwallet and `lnd` test matrices on SQLite first, then PostgreSQL.
- Migrate copies of real wallets and compare balances, derivation, transactions,
  pending sweeps, leases, and restart behavior.
- Ship SQL as opt-in. Keep KV as the default and rollback source for at least
  one release cycle.

Exit gate: `lnwallet` wallet/signer interfaces and behavior are unchanged. The
btcwallet adapter may contain narrowly additive backend configuration and
construction logic. The full integration matrix is green, and canary
migrations have a tested rollback path.

## Verification Matrix

The minimum gate for every port PR is:

```text
btcwallet API diff:       no breaking exported changes
btcwallet unit/race:      KV green
store integration:        SQLite + PostgreSQL green
lnd compile:              unmodified source, root + changed-leaf replaces
```

Before enabling a runtime SQL backend, add:

```text
wallet E2E:
  KV, SQLite, PostgreSQL
  btcd, neutrino, bitcoind
  create, load, sync, fund, sign, publish, restart, rescan, reorg, recover

PSBT and signing:
  FundPsbt with account/scope and WithUtxoFilter
  DecorateInputs
  FinalizePsbt
  custom lnd key scope 1017
  imported keys and taproot scripts
  Lightning input tweaks

migration:
  historical fixtures
  interruption and retry
  wrong network/passphrase/version
  semantic digest parity
  reopen, rescan, rollback
```

The `lnd` gate should include at least:

```text
go build ./...
go test ./lnwallet/btcwallet ./keychain ./lnrpc/walletrpc
```

The integration suite should cover PSBT fund/sign/finalize, custom input locks,
taproot import/signing, wallet import, sweeps, rescan/sync, restart, and recovery.

## Merge and Stop Rules

- Do not merge a storage PR that requires a public API adaptation in `lnd`.
- Do not merge SQL runtime selection until wallet-level SQL end-to-end tests
  exist. Store tests alone are insufficient.
- Do not call schema migrations a wallet migration. The project is not migrated
  until an existing `wallet.db` is imported and verified.
- Do not rewrite lifecycle, sync, recovery, signing, or encryption to work around
  an SQL integration problem. Stop and fix the internal storage boundary.
- Do not remove or skip an existing test to make backend parity pass.
- Do not close old feeder PRs until their commit-map disposition is public.
- Do not remove KV until SQL migration and rollback have shipped and operated in
  production for at least one release cycle.

## Definition of Done

The SQL port is done when all of the following are true:

- SQLite and PostgreSQL run the existing wallet end to end.
- The public btcwallet API used by `lnd` is source compatible.
- Unmodified `lnd` compiles and its btcwallet, keychain, PSBT, signer, sweep,
  rescan, restart, and recovery tests pass against the SQL wallet.
- Existing KV wallets migrate offline, deterministically, and reversibly.
- KV, SQLite, and PostgreSQL agree on wallet-visible behavior.
- Every source commit and feeder PR has a recorded attribution/disposition.
- The role-interface, controller/syncer, and key-vault projects have their own
  post-port roadmap and are no longer prerequisites for SQL.

At that point, we will have completed the port-first operational goal adopted
here: the same wallet that `lnd` already knows how to use, backed by SQL. Then
we can decide how much of the rewrite we still want, with a working SQL system
beneath it and a much smaller regression surface.

## Feeder Inventory

The direct `interface-wallet` targets are:

`#1050`, `#1052`, `#1059`, `#1068`-`#1076`, `#1084`, `#1085`, `#1091`,
`#1092`, `#1095`, `#1100`, `#1108`, `#1110`, `#1118`, `#1126`-`#1130`,
`#1137`, `#1144`-`#1146`, `#1148`, `#1152`, `#1155`-`#1157`, `#1159`-`#1161`,
and `#1164`.

The 103 direct `sql-wallet` targets are:

`#1051`, `#1065`, `#1096`, `#1099`, `#1101`, `#1111`, `#1115`, `#1121`,
`#1125`, `#1131`, `#1132`, `#1134`-`#1136`, `#1138`, `#1139`, `#1141`-`#1143`,
`#1147`, `#1154`, `#1158`, `#1162`, `#1165`, `#1166`, `#1168`-`#1174`, `#1181`,
`#1182`, `#1185`-`#1190`, `#1192`, `#1193`, `#1195`-`#1202`, `#1204`, `#1206`,
`#1208`-`#1212`, `#1214`, `#1216`, `#1217`, `#1219`-`#1225`, `#1227`-`#1233`,
`#1237`-`#1248`, `#1252`-`#1254`, `#1256`-`#1258`, `#1260`-`#1263`, `#1265`,
`#1267`-`#1269`, `#1273`, `#1277`, and `#1279`.

The intermediate feeder stack contains `#1203`, `#1215`, `#1218`, `#1236`,
`#1249`, `#1255`, and the open runtime tail `#1270`-`#1272`.

This inventory is a starting point for the commit map, not a claim that every
PR should be transplanted. Its purpose is to prevent quiet loss of work while
we cut the port away from the rewrite.

Closed PR heads are not reliable historical evidence by themselves. PR #1181,
for example, now points at a force-pushed, unrelated one-file change despite its
architecture-modernization title. The commit map must use commits actually
reachable from the pinned umbrella tips and the canonical feeder merge commits,
not a closed PR's current head.
