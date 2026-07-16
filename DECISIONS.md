# Salvage Stage 3 Decisions

This file records judgment calls made while implementing Stage 3 increments on
the salvage `#1296` foundation. Each section is self-contained.

## Phase 0A: schema identity

Implements the schema-family identity gate only (NOT the Stage 2 bug fixes,
which are a separate increment).

### Family string and generation scheme

- **Family:** `"btcwallet-salvage"`. Stable identifier of the salvage schema
  lineage. It never changes for this lineage and is what distinguishes a salvage
  database from a foreign (e.g. normalized) btcwallet SQL schema.
- **Generation:** monotonically increasing integer starting at `1`. Current
  `Generation = 1`. A newer database (generation greater than this binary's
  `Generation`) is rejected with `ErrNewerGeneration`.
- **MinGeneration = 1:** oldest generation this binary can open. A database
  below it is rejected with `ErrUnsupportedGeneration`. With the current values
  only generation `1` is valid; generation `0`/negative is unsupported. When a
  future runtime migration bumps `Generation`, raise `MinGeneration` only when
  an old generation truly can no longer be opened.
- Constants live in the shared package so both dialects and future callers use
  one source of truth: `wallet/internal/sql/schemaid`.

### Where the constants, errors, and decision live (shared package)

- New package `wallet/internal/sql/schemaid` holds: the family/generation
  constants, the five sentinel errors, the `Marker`/`Action` types, the pure
  `Evaluate(tables, marker, dirty) (Action, error)` classifier, and the
  `Ensure(ctx, Backend)` orchestrator.
- The dialect packages (`sql/sqlite`, `sql/pg`) implement `schemaid.Backend`
  with raw `database/sql` (table listing, marker read, dirty read, marker
  insert, and a call through to their existing `ApplyMigrations`). This is the
  "share logic where practical" split: the risky classification + ordering is
  written and tested once; only the dialect-specific SQL (placeholders,
  `sqlite_master` vs `information_schema`, BLOB/BYTEA vs types) is duplicated.
- Sentinels are shared (not per-dialect) so a caller handling both backends
  checks one set via `errors.Is`, e.g. `schemaid.ErrForeignSchemaFamily`.

### Sentinel errors (all in `schemaid`)

`ErrForeignSchemaFamily`, `ErrDirtySchema`, `ErrNewerGeneration`,
`ErrUnsupportedGeneration`, `ErrUnknownSchema`. Returned unwrapped from
`Evaluate`/`Ensure` so `errors.Is` and equality both work.

### Fingerprint criteria

- **Salvage fingerprint (pre-marker):** the full set of the 14 tables created by
  migrations `000001`..`000010`: `blocks`, `wallets`, `wallet_sync_states`,
  `address_types`, `key_scopes`, `accounts`, `addresses`, `transactions`,
  `transaction_inputs`, `transaction_labels`, `credits`,
  `active_credit_incidences`, `credit_spends`, `utxo_leases`. All 14 must be
  present to backfill a marker.
- **Foreign markers:** `utxos`, `tx_replacements` — tables that exist in the
  separate normalized btcwallet schema and never in the salvage schema. Their
  presence (in an unmarked DB) => `ErrForeignSchemaFamily`, even if some salvage
  tables also happen to exist and even if the DB is dirty.
- **Unknown:** a non-empty, unmarked DB with no foreign markers that does not
  contain the full salvage set => `ErrUnknownSchema`.
- The golang-migrate bookkeeping table `schema_migrations` is excluded when
  deciding whether an unmarked DB is "empty".

### Classification and ordering (`Evaluate`)

Facts gathered before any mutation: table list, the marker row (if the identity
table has one), and the migration `dirty` flag.

- **Marked DB** (identity row present): `family != Family` -> foreign; else
  `dirty` -> dirty; else `generation > Generation` -> newer; else
  `generation < MinGeneration` -> unsupported; else `ActionValidateOnly`.
- **Unmarked, empty:** `dirty` -> dirty (failed first migration); else
  `ActionBootstrap`.
- **Unmarked, non-empty:** foreign markers -> foreign; else `dirty` -> dirty;
  else not-full-salvage-set -> unknown; else `ActionBackfill`.

Rationale for order: identity/family is decided first (is this even our
database?) before reporting dirty; foreign is decided before dirty for unmarked
DBs so a recognizably-foreign DB is never misreported as merely dirty.

### Gate ordering relative to the migration runner

`Ensure` = inspect (no mutation) -> classify/reject -> `ApplyMigrations()` ->
insert the marker row when the action is `Bootstrap` or `Backfill` (skip for
`ValidateOnly`). The marker **row** is inserted by Go **after** migration 11
creates the **table**; migration 11 only does `CREATE TABLE` and hardcodes no
row, so Go owns the family/generation constants. This ordering also means a
crash between `ApplyMigrations` and the insert leaves an identity table with no
row, which the next open classifies as `Backfill` and repairs idempotently.

### Migration 11

- `000011_schema_identity.{up,down}.sql` added to both
  `wallet/internal/sql/sqlite/migrations/` and `.../pg/migrations/`
  (auto-embedded by the existing `//go:embed migrations/*.sql`).
- Table `btcwallet_schema_identity(id, family, generation, created_at)`, single
  row pinned via `id INTEGER PRIMARY KEY CHECK (id = 1)`. Dialect types mirror
  existing migrations: sqlite `INTEGER`/`TEXT`; pg `INTEGER`/`BIGINT`/`TEXT`
  (`generation`/`created_at` as `BIGINT`, matching `block_timestamp`).
  `created_at` is Unix seconds.

### Where the gate is hooked (production path)

- No production code called `ApplyMigrations` yet — only tests did. So the gate
  is the new canonical migrate entry point:
  - `EnsureSchemaFamily(ctx, db)` (each dialect): gate + `ApplyMigrations` +
    marker.
  - `OpenAndMigrate(ctx, cfg)` (each dialect): `Open` + `EnsureSchemaFamily`,
    the "real open/migrate path" a future wallet open path should call.
- `ApplyMigrations` stays exported and unchanged so existing migration
  round-trip / conformance tests keep using it directly.
- **Next increment:** when the wallet SQL open path is built, it must call
  `OpenAndMigrate`/`EnsureSchemaFamily` instead of a bare `ApplyMigrations`.

### sqlc

- The gate uses raw `database/sql` and does NOT reference generated sqlc code,
  so no query change or regeneration is needed for the gate itself.
- BUT sqlc emits a model struct per table in the schema, so `make sql` will add
  a `BtcwalletSchemaIdentity` model to `models.go` for both dialects. This does
  not affect `go build`/`vet`/`test` (nothing references the model). It WILL
  make `make sqlc-check` show a diff. **Next increment / pre-PR:** run the
  pinned Docker `make sql` (sqlc v1.30.0) to add the model and keep
  `sqlc-check` green. Local sqlc here is v1.31.1, so it was deliberately NOT
  run (version drift would rewrite all generated files).

### Verification status

- `GOWORK=off go build ./...` — pass.
- `GOWORK=off go vet ./wallet/internal/sql/...` — pass (and
  `-tags test_db_postgres` — pass).
- SQLite gate tests + full `sql/sqlite` package — pass.
- `schemaid` pure-logic tests — pass.
- PostgreSQL gate tests + full `sql/pg` tagged package — **executed and passed**
  against real `postgres:18-alpine` testcontainers (Docker was available).
- `wallet/internal/db/itest` (uses `ApplyMigrations`) — pass.

## Phase 0A: KV Stage-2 fixes

Correctness fixes to the bucket-bound `waddrmgr` KV store (`store_kv.go`,
`db.go`) identified in review of the `#1296` tip. Scope: KV halves only; the SQL
halves are owned by a separate increment. Regression tests live in
`waddrmgr/store_kv_test.go` (table-driven, `require`, positive+negative).

### 1. KV replacement retains private material (HIGH)

`PutManagerState` and `SetCoinTypeKeys` are defined as full replacement but
delegated to the skip-nil legacy writers (`putMasterKeyParams`, `putCryptoKeys`,
`putMasterHDKeys`, `putCoinTypeKeys`), so a watch-only replacement retained the
previous encrypted private keys while reporting `WatchOnly`.

- **Fix:** the legacy writers are unchanged (still skip-nil for partial legacy
  updates). Replacement semantics are enforced in the Store methods:
  `PutManagerState` now deletes every optional main-bucket key whose field is
  nil (`mpriv`, `cpriv`, `cscript`, `mhdpriv`, `mhdpub`) via the small
  `deleteMainKeyIfAbsent` helper; `SetCoinTypeKeys` deletes `ctpriv` when the
  private key is nil.
- **Judgment:** required *public* fields (`mpub`, `cpub`, `ctpub`) keep put-only
  semantics — a valid replacement always supplies them, and deleting them would
  corrupt the manager. Only optional/private material is delete-on-nil.

### 2. Private-key deletion missed secret taproot scripts (KV half)

Legacy `deletePrivateKeys` handled `adtWitnessScript` but not
`adtTaprootScript` (type 4), leaking secret tapscripts on watch-only
conversion. Taproot shares the witness-script row codec, so the fix is
`case adtWitnessScript, adtTaprootScript:`. This corrects both the Store and the
legacy `ConvertToWatchingOnly` path (same helper).

### 3. KV account name-index inconsistency

- `PutAccount` wrote a new name index without removing the old one (stale name
  stayed resolvable). **Fix:** on replace, if the existing account's name
  differs, delete the old name index first.
- `RenameAccount` could overwrite a *different* account's name index. **Fix:**
  reject with `ErrDuplicateAccount` when the target name belongs to another
  account (via `fetchAccountByName`), then delegate index maintenance to
  `PutAccount` (dropped the now-redundant explicit `deleteAccountIDIndex` /
  `deleteAccountNameIndex`).
- **Judgment:** legacy `ScopedKeyManager.RenameAccount` rejects renaming to *any*
  existing name including the account's own; the Store instead allows renaming
  an account to its own current name (a no-op) and rejects only *other*
  accounts' names, matching the task's "another account" wording.

### 4. KV address replacement left a stale account index

Re-homing an address to a different account wrote the new account-address index
without removing the old, so `AccountAddresses` returned it under both accounts.

- **Fix:** `putAddress` now reads the reverse index and, when the owning account
  changed, deletes the stale `addracctidx/<oldAccount>/<addrHash>` entry before
  writing the new one. Placed in the shared helper so the invariant holds for
  all callers; it never fires for legacy callers (they always re-write an
  address under its existing account), so legacy behavior is unchanged.

### 5. StartBlock.Timestamp loss — narrowed contract (judgment call)

The legacy start-block encoding is a fixed 36-byte `<height><hash>` blob and has
always dropped `BlockStamp.Timestamp` (even though `Create` seeds the genesis
timestamp). `SyncedTo` uses a separate 40-byte format that *does* keep its
timestamp.

- **Decision: document the narrowed contract, do NOT change the format.**
  Reasons: (a) matches long-standing legacy semantics; no code reads a non-zero
  `StartBlock.Timestamp`; (b) a format change is out of scope for a KV
  correctness fix; (c) crucially, widening the reader to accept 40 bytes would
  make new 40-byte writes fail an older binary's strict `len == 36` check —
  a real downgrade-compat hazard. Only `SyncedTo`/`BirthdayBlock` timestamps
  round-trip.
- Documented on `FetchStartBlock`/`putStartBlock` (db.go) and
  `SyncState`/`PutSyncState` (store_kv.go); asserted by
  `TestKVStartBlockTimestampNarrowed`.

### 6. No-account sentinel — KV already correct (no code change)

Claim: nullable last-account can decode as account 0 instead of the no-account
sentinel. In the **KV** layer this is already correct: `fetchLastAccount`
returns `(1<<32)-1` (MaxUint32) when the `lastaccount` key is absent and the
decoded value otherwise, so account 0 and "no account" stay distinct and
round-trip through `SetLastAccount`/`KeyScope`. The nullable-decodes-as-0 bug is
SQL-side (separate owner). **No KV code change was fabricated**; a regression
test (`TestKVLastAccountNoAccountSentinel`, decode + Store round-trip) locks in
the invariant.

### Test-harness note (init warm-up)

The new tests run `t.Parallel()` and each calls `setupManager`, which runs
`Create` against the shared package-global `rootKey`. `Create` neuters that key,
and `hdkeychain`'s `pubKeyBytes` lazily memoizes the public key on first use —
concurrent first calls race on that cache field under `-race` (a pre-existing
harness artifact, not a production race). `store_kv_test.go` adds a one-line
`init()` that primes `rootKey.Neuter()` once before any test, keeping the tests
parallel and clean under `-race`. (`gochecknoinits` is disabled in
`.golangci.yml`, and `log.go` already uses `init()`.)

### Verification status

- `GOWORK=off go build ./...` — pass (exit 0).
- `GOWORK=off go vet ./waddrmgr/...` — pass (exit 0).
- `GOWORK=off go test ./waddrmgr/...` — pass (full package).
- `GOWORK=off go test ./waddrmgr/... -race` — pass (full package).
- `gofmt -l` on changed files — clean; changed lines within ~80 cols.

## Phase 0A: SQL Stage-2 fixes

Correctness fixes to the SQL manager/transaction store identified in review of
the `#1296` tip. Scope: SQL halves only (SQLite + PostgreSQL); the KV halves are
owned by the separate "Phase 0A: KV Stage-2 fixes" increment above. Owned
files: `wallet/internal/sql/{sqlite,pg}/queries/*.sql`, the regenerated
`.../sqlc/**`, `wallet/internal/db/sqlstore/*.go`, and
`wallet/internal/db/{sqlite,pg}/store.go`. Regression tests live in the SQL
conformance harness `wallet/internal/db/itest/manager_store_test.go`, which runs
against SQLite (always) and PostgreSQL (`-tags test_db_postgres`).

### 1. Private-key deletion missed secret taproot scripts (SQL half)

`DeleteAddressPrivateKeys` (both dialects) cleared `encrypted_script` for
address types 2 (`AddressScript`, unconditional) and 3 (`AddressWitnessScript`,
when `is_secret_script`) but omitted type 4 (`AddressTaprootScript`), leaking
secret tapscripts on watch-only conversion.

- **Fix:** add `WHEN address_type = 4 AND is_secret_script = TRUE THEN NULL` to
  the `CASE`, mirroring the type-3 secret-script rule. Witness and taproot
  scripts share the secret/public distinction, so the condition matches. This
  is the SQL twin of the KV `case adtWitnessScript, adtTaprootScript:` fix
  above; both clear secret scripts only, retaining public ones.

### 2. Sticky-used upsert divergence

The `PutManagerAddress` upsert assigned `used = excluded.used`. A monotonic
`BEFORE UPDATE OF used` trigger (`trg_addresses_used_is_monotonic`) aborts a
true->false transition, so re-putting an already-used address with `Used=false`
*errored* in SQL where the legacy KV silently keeps the sticky bit.

- **Fix:** `used = addresses.used OR excluded.used` (both dialects). The OR is
  monotonic — it never lowers a set bit — so the trigger never fires and the
  re-put is a no-op instead of an error, matching KV. The table-qualified
  `addresses.used` form is accepted by both SQLite and PostgreSQL upserts
  (validated in-process by the SQLite run and against real PostgreSQL).
- **Test:** `sticky used monotonic` covers both the true->false no-op (the bug)
  and false->true (ensures the OR does not freeze the bit).

### 3. SQL SetSyncedTo missing legacy sync semantics

`addrStore.SetSyncedTo` recorded the block and synced height but omitted two
durable behaviors of legacy `waddrmgr.PutSyncedTo`.

**Intended contract (defined for the salvage height-keyed schema):**

- *Reset (block == nil):* fall back to the wallet start block. Already present;
  kept. Matches legacy `Manager.SetSyncedTo(nil)`.
- *Predecessor guard:* for a non-genesis tip (`height > 0`), once the birthday
  block is recorded the block at `height-1` must already exist, else a legacy
  `ErrBlockNotFound` manager error. Gated on the birthday block because the
  recent-block index is intentionally sparse during initial sync (exactly the
  legacy `FetchBirthdayBlock` gate). Checked before writing the block, so a
  rejected update writes nothing.
- *Same-height replace:* handled by the existing `PutBlock` upsert
  (`ON CONFLICT (block_height) DO UPDATE`), matching legacy `addBlockHash`
  overwrite. Now covered by a test.
- *Rewind:* setting a lower tip whose predecessor is known succeeds and lowers
  `synced_block_height`. Now covered by a test.
- *Recent-block retention:* prune the block that ages out of the reorg window
  (`height - waddrmgr.MaxReorgDepth`), matching the legacy per-tip prune.

**Judgment call — retention prune on a shared, foreign-keyed blocks table.**
The legacy prune deletes one stale hash from a *per-wallet* height→hash index
independent of transaction storage. The salvage schema instead has one *global*
`blocks` table referenced by `transactions` and `wallet_sync_states` with
`ON DELETE RESTRICT`. A naive `DELETE` at the stale height would (a) fail the FK
and make `SetSyncedTo` error where legacy succeeds, and (b) be wrong
cross-wallet (it could remove a block another wallet still references).

- **Decision:** add `PruneStaleSyncBlock`, a *guarded* single-statement delete
  that removes the stale block only when no transaction and no wallet sync
  state (start/synced/birthday, any wallet) still references it. This bounds
  storage in the common single-wallet case as legacy does, never violates
  referential integrity, and never removes a block another wallet needs. It
  prunes only the single block at `height - MaxReorgDepth` per call, matching
  legacy's one-per-tip behavior (heights <= `MaxReorgDepth` are no-ops).
- **Residual limitation (deferred to Phase 0B):** a block inside another
  wallet's reorg window but not FK-referenced by it is still retained
  (correct-leaning); a strict per-wallet rolling window is not expressible on
  the shared height-keyed table. Phase 0B's block-lifecycle redesign (surrogate
  IDs, per-wallet incidences, explicit orphan pruning) supersedes this.
- **Wiring:** `PruneStaleSyncBlock` is a new query in `blocks.sql` (both
  dialects), added to the `sqlstore.Queries` interface and the SQLite/PostgreSQL
  adapters; the predecessor/birthday check reuses the existing `GetSyncState` +
  `GetBlockByHeight`. Legacy ordering is preserved: predecessor guard → write
  block → prune stale → update synced height.
- **Tests:** `synced-to semantics` sub-tests cover missing predecessor,
  same-height replace, rewind, and retention (unreferenced stale block pruned,
  referenced stale block retained).

### sqlc regeneration

Query text changed for fixes 1-3, so `wallet/internal/sql/{sqlite,pg}/sqlc/**`
was regenerated with the repo's pinned Docker sqlc (`make sqlc`, v1.30.0); local
sqlc is v1.31.1 and was not used. Regeneration is idempotent (a second
`make sqlc` produced no further diff). The regen also materialized the
`BtcwalletSchemaIdentity` model in `sqlc/models.go` (both dialects) from the
co-agent's untracked migration `000011`; this is a deterministic consequence of
the shared on-disk schema and was kept so the generated tree stays consistent
(the schema-identity increment owns that migration). `make sqlc-check` reports
"not up-to-date" solely because the changes are uncommitted (no-commit
constraint) and the co-agent's `000011` / `schema_identity.go` / `schemaid/`
files are untracked under `SQL_DIR`; the generated code itself matches the
queries.

### Not in this increment

The KV section flags a SQL last-account nullable-decodes-as-0 sentinel item;
that is a separate fix outside these three assigned corrections and was not
touched here.

### Verification status

- `GOWORK=off go build ./...` — pass (exit 0).
- `GOWORK=off go vet ./wallet/internal/...` — pass (exit 0; also `-tags
  test_db_postgres` on the itest package).
- `GOWORK=off go test ./wallet/internal/sql/... ./wallet/internal/db/sqlstore/...
  ./wallet/internal/db/itest/...` — pass.
- `TestPostgresManagerStore` (`-tags test_db_postgres`, real
  `postgres:18-alpine` testcontainer) — pass, all sub-tests including the three
  new ones.

## Phase 0A: finish (sentinel + conformance vector)

The final Phase 0A increment: the SQL no-account sentinel (finding #9 SQL half),
the self-fulfilling address-hash assertion (finding #8), and extending the
shared conformance vector to run against KV, SQLite, and PostgreSQL toward the
Phase 0A exit gate.

### 1. SQL no-account sentinel (finding #9, SQL half)

**Where the bug was.** The nullable last-account column is
`key_scopes.last_account_number`. Both SQL read adapters decoded a NULL as
account `0`:

```go
var lastAccount uint32            // zero value on NULL
if row.LastAccountNumber.Valid {
        lastAccount, err = sqlstore.CheckedUint32(...)
}
```

so a scope that had never allocated an account was indistinguishable from a
scope whose last account really is `0`. The legacy KV `fetchLastAccount` instead
returns the `(1<<32)-1` no-account sentinel for the absent key.

**Fix.**

- Added the shared exported constant `waddrmgr.NoAccountAllocated = (1<<32)-1`
  (single source of truth). The KV `fetchLastAccount` now returns it instead of
  the inline magic number — a pure no-op refactor of the already-correct KV
  half; the value is identical (`^uint32(0)`), so KV behavior is unchanged and
  the KV agent's `TestKVLastAccountNoAccountSentinel` still passes.
- Read path (`sqlite`/`pg` `waddrmgr_queries.go`): initialize `lastAccount` to
  `waddrmgr.NoAccountAllocated`; only override from a valid (non-NULL) value.
- Write path: new shared helper `sqlstore.NullableLastAccount(uint32)
  sql.NullInt64` stores the sentinel as SQL `NULL` and any other value (incl. a
  real `0`) as a valid integer. Used by both dialects in `PutKeyScope` and
  `SetLastAccount`.

Round-trip is now symmetric and distinct from account 0: sentinel ⟷ NULL ⟷
sentinel; `0` ⟷ `0`; `N` ⟷ `N`. A legacy row that happened to store the literal
`4294967295` still decodes to the sentinel via `CheckedUint32`.

**No sqlc regeneration.** The generated params were already nullable
(`PutKeyScopeParams.LastAccountNumber sql.NullInt64`,
`UpdateLastAccountNumberParams.LastAccountNumber sql.NullInt64`), so the fix is
Go-only. No `*.sql` or `*.sql.go` file was touched, and `make sqlc` was not run.

**Parity test.** `testLastAccountSentinel` in the shared vector runs the same
assertions against KV, SQLite, and PostgreSQL: a scope seeded with the sentinel
reads back the sentinel, a scope seeded with `0` reads back `0`, and
`SetLastAccount` round-trips `{0, sentinel, 5, sentinel}` distinctly. Because the
identical assertions pass on all three backends, this is the KV-vs-SQL parity
check.

### 2. Self-fulfilling address-hash assertion (finding #8)

`testAddressManagerPersistence` copied the returned `Hash` into the expectation
(`chainAddress.Hash = gotChain.Hash`) before comparing, so a wrong hashing
algorithm was undetectable. Both the legacy KV store (`store_kv.go`) and the SQL
store (`sqlstore/store.go`) derive the durable identifier as
`sha256.Sum256(addressID)`. The assertion now computes that expectation
independently from the address ID input:

```go
wantChainHash := sha256.Sum256(chainAddressID)
chainAddress.Hash = wantChainHash[:]
require.Equal(t, chainAddress, gotChain)
```

The same independent derivation is used for the witness address and for every
form in the new `testAddressForms` / `testCloseReopen` cases.

### 3. SQL RenameAccount collision parity (surfaced by the vector)

The neutral `rename account collision` case revealed that the SQL
`RenameAccount` did not map an `accounts(scope_id, account_name)` unique-key
collision to the typed `waddrmgr.ErrDuplicateAccount` (the bare `UPDATE` surfaced
a raw driver error), whereas the legacy manager and the KV store both return
`ErrDuplicateAccount`. Fixed in `sqlstore.addrStore.RenameAccount` with a
pre-check that mirrors the KV fix: look up the target name; if it is owned by a
*different* account, return `ErrDuplicateAccount`; renaming to a free name or to
the account's own current name stays permitted. Dialect-agnostic (no SQL error
parsing). This is the only production behavior change item 3 required; the
watch-only manager-replacement HIGH fix was already correct on the SQL side
because `PutManagerState` is an unconditional full-column `UPDATE` (nil private
fields become `NULL`).

### 4. Shared conformance vector across KV, SQLite, PostgreSQL

`managerStoreHarness` gained an optional KV backend (`kv *kvBackend`, new
`kv_test.go`) alongside the existing SQL backends, plus a `reconnect`/`reopen`
path for close/reopen. The KV backend builds a `db.Store` from a **bare
watch-only** `waddrmgr.Manager` (`waddrmgr.Create` with a nil root key seeds no
default scopes) + a `wtxmgr.Store`, wrapped by `kvdb.NewStore`. The bare
watch-only manager matches the empty starting state of the SQL `createWallet`
fixture, so the *same* parameterized cases and assertions run on all three
backends. `createWallet`, `syncedHeight`, and `blockHash` dispatch to
store-based reads for KV; the SQL fixtures stay for the SQL backends.

Case registration in `testManagerStore` is split: the backend-neutral vector
runs on every backend; the transaction-incidence cases that depend on the SQL
fixture schema run only when `harness.kv == nil`.

**Exit-gate coverage matrix** (case × backend, ✓ = runs and passes):

| Case | KV | SQLite | Postgres |
|---|:--:|:--:|:--:|
| all five legacy address forms (`address forms`) | ✓ | ✓ | ✓ |
| taproot (type 4) secret-script deletion (`script private key deletion`) | ✓ | ✓ | ✓ |
| private-material removal on manager replacement (HIGH) | ✓ | ✓ | ✓ |
| sticky-used monotonic replace | ✓ | ✓ | ✓ |
| account name dedup | ✓ | ✓ | ✓ |
| rename collision (`ErrDuplicateAccount`) | ✓ | ✓ | ✓ |
| address re-home leaves no stale account index | ✓ | ✓ | ✓ |
| no-account sentinel round-trip (`last account sentinel`) | ✓ | ✓ | ✓ |
| SetSyncedTo: missing predecessor / same-height / rewind | ✓ | ✓ | ✓ |
| rollback after a partial write (`partial write rollback`) | ✓ | ✓ | ✓ |
| close/reopen persistence | ✓ | ✓ | ✓ |
| full persistence round-trip (`address manager persistence`) | ✓ | ✓ | ✓ |
| SetSyncedTo: stale-block prune (`recent block retention`) | — | ✓ | ✓ |
| transaction-incidence rollback / duplicate incidence | — | ✓ | ✓ |
| birthday verification / wtxmgr compatibility | — | ✓ | ✓ |

**Deliberately deferred / backend-scoped (not run on KV):**

- **Stale-block prune retention.** Exercises the SQL FK-guarded
  `PruneStaleSyncBlock` against the shared `blocks` table with transaction
  fixtures. The KV recent-block index is a different per-wallet model; its prune
  is covered by `waddrmgr` package tests. Kept SQL-only.
- **Transaction-incidence rollback, duplicate incidence, birthday
  verification, wtxmgr compatibility.** These depend on the SQL incidence
  fixture schema (raw `transactions`/`credits`/`active_credit_incidences`) that
  has no KV counterpart at this layer; the KV transaction surface is covered in
  `wallet/internal/db/kvdb` and `wtxmgr`. The neutral `partial write rollback`
  case covers transaction *atomicity* on all three backends.
- **StartBlock.Timestamp** is asserted only up to the narrowed Store contract:
  `testAddressManagerPersistence` drops it before comparing `SyncState`, because
  the legacy KV encoding does not persist it (documented finding #5). Height and
  hash round-trip on all backends; SyncedTo/Birthday timestamps round-trip.

### Verification status

- `GOWORK=off go build ./...` — pass (exit 0).
- `GOWORK=off go vet ./wallet/internal/...` — pass (exit 0; also `-tags
  test_db_postgres` on the itest package).
- `GOWORK=off go test ./wallet/internal/sql/... ./wallet/internal/db/...` —
  pass (SQLite + KV conformance).
- `GOWORK=off go test -race` on the SQLite + KV itest — pass.
- `GOWORK=off go test ./waddrmgr/...` — pass.
- `TestPostgresManagerStore` (`-tags test_db_postgres`, real
  `postgres:18-alpine` testcontainer) — pass; all 22 sub-tests including every
  new neutral case.
- `make sqlc` was not run (no query change); consequently `make sqlc-check` was
  not exercised for this increment.
