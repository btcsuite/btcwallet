# ADR 0014: Durable SQL Database Identity

## Status

- **Status:** Accepted
- **Date:** 2026-08-19

## Relationships

- **Amends:** None.
- **Supersedes:** None.
- **Amended by:** None.
- **Superseded by:** None.

## 1. Problem

Migration version alone does not prove that a SQL namespace belongs to the
btcwallet role wallet or the requested Bitcoin network. A foreign,
wrong-network, malformed, dirty, or newer namespace must be rejected before
btcwallet changes durable state.

SQLite owns a complete database file. PostgreSQL owns the fixed `btcwallet`
schema within a database that may also contain lnd or other application data.

## 2. Context

The current SQLite path enables WAL before constructing a migration driver,
which may create its default migration table. The PostgreSQL path creates its
default migration table and wallet objects through the ambient `search_path`.
Neither path validates durable ownership before mutation. The SQLite driver
lock is process-local, and neither driver provides the required identity-first,
caller-owned atomic transaction.

### Constraints

- Identity must be validated before persistent pragmas, migration metadata,
  migrations, sqlc queries, or wallet access can mutate the namespace.
- Only an empty unmarked namespace is adoptable. Populated unmarked and legacy
  namespaces require a separate conversion decision.
- Concurrent first openers must use database-native exclusion, not a
  process-local correctness lock.
- One Store open performs one read-only preflight and one locked recheck.
  Ordinary wallet queries perform no identity checks.
- Identity is independent of ordinary migration progress and runtime wallet
  parameters.
- This decision adds no sidecar lock, create manifest, recovery state machine,
  Store implementation, schema change, generated output, or migration.

## 3. Decision

### Identity contract

Every role-wallet SQL namespace contains exactly one immutable identity row:

| Field | Required value and encoding |
| --- | --- |
| `schema_family` | Exact case-sensitive UTF-8 text `btcwallet-sql` |
| `identity_generation` | Integer `1` |
| `genesis_hash` | Exact 32 bytes from `chaincfg.Params.GenesisHash[:]` |
| `network_magic` | Mathematical unsigned 32-bit `Params.Net` value |
| `signet_challenge_digest` | Trusted 32-byte signet digest; NULL otherwise |

Genesis bytes use `chainhash.Hash` array order, not the reversed display order
from `Hash.String()`. PostgreSQL stores network magic in `BIGINT`, preserving
the full unsigned uint32 value. Comparisons are exact and byte-for-byte.

Generation 1 is the only supported generation. A future generation requires a
superseding decision with an explicit compatibility and transition path; it is
not an ordinary schema migration.

The identity excludes `Params.Name`, coinbase maturity, address and WIF
prefixes, Bech32 HRP, HD private and public versions, and BIP44 coin type. Those
values affect presentation, policy, import/export, or per-wallet and per-scope
behavior; their existing subsystems remain responsible for them.

### Signet identity

All signets share one genesis block, and network magic contains only four bytes
of the challenge digest. The full identity input is:

```text
DoubleSHA256(byte(len(challenge)) || challenge)
```

This is the one-byte-length-prefixed serialization used by
`chaincfg.CustomSignetParams`. Manager configuration must carry the trusted
32-byte result in returned array order, derived from the same challenge used to
construct those params. Before database access, the little-endian uint32 from
its first four bytes must equal `uint32(Params.Net)`.

A network with the fixed signet genesis is signet regardless of `Params.Name`
and requires the digest. A non-signet requires NULL. Missing or internally
inconsistent input is rejected before database access. An
equal-magic/different-challenge stored identity is rejected during preflight
before mutation.

### Metadata ownership

PostgreSQL stores every role-wallet object in schema `btcwallet` and never
depends on the ambient `search_path`. SQLite treats the complete file as its
namespace. Their identity tables are:

| Backend | Identity table |
| --- | --- |
| SQLite | `btcwallet_database_identity` |
| PostgreSQL | `btcwallet.database_identity` |

The columns are `id`, `schema_family`, `identity_generation`, `genesis_hash`,
`network_magic`, and `signet_challenge_digest`. `id` is the primary key,
constrained to 1. Required text is nonempty, integer fields enforce their
ranges, and byte fields enforce their lengths. SQLite uses `INTEGER` for the
three integers, `TEXT` for family, and `BLOB` for hashes. PostgreSQL uses
`SMALLINT` for `id`, `BIGINT` for generation and magic, `TEXT` for family, and
`BYTEA` for hashes.

After bootstrap the table has exactly one row selected by `id = 1`. A wrong
shape, zero or multiple rows, a NULL required field, or an invalid value is
malformed and foreign.

Ordinary migration state remains separate:

| Backend | Migration-state table |
| --- | --- |
| SQLite | `btcwallet_schema_migrations` |
| PostgreSQL | `btcwallet.schema_migrations` |

Both tables use golang-migrate's standard `version` and `dirty` columns. An
empty table is the sole clean no-version state. After the first migration the
table contains exactly one row with the highest applied positive version and a
logical Boolean dirty value. SQLite uses `INTEGER` and 0/1; PostgreSQL uses
`BIGINT` and `BOOLEAN`. When identity exists, a missing migration-state
relation, NULL, zero, invalid Boolean, or multiple rows are malformed. Identity
generation never derives from or tracks migration version.

The existing golang-migrate database drivers own transaction boundaries and
cannot satisfy the atomic initialization contract. The initialization executor
must execute migration bodies and maintain the standard version row through
the caller-owned pinned transaction without creating metadata or starting an
independent transaction first.

### Preflight and classification

Requested identity is validated in memory before database access. Each open
then performs a logically non-mutating preflight:

- SQLite reads `sqlite_schema` and recognized metadata through a read-only
  connection, ignoring only SQLite-owned internal objects.
- PostgreSQL reads the fixed schema through catalog queries. Before first
  adoption, it also scans non-system schemas for these reserved legacy table
  names: `blocks`, `wallets`, `wallet_secrets`, `wallet_sync_states`,
  `address_types`, `key_scopes`, `key_scope_secrets`, `accounts`,
  `account_secrets`, `addresses`, `derived_addresses`, `address_secrets`,
  `transactions`, `utxos`, `tx_replacements`, and `utxo_leases`.

Any reserved table name outside the fixed schema rejects first adoption,
regardless of shape, so partial or malformed unqualified wallets fail closed.
An unrelated migration-state table alone is not a footprint. After a valid
identity exists in `btcwallet`, objects outside that schema are irrelevant.

Logically non-mutating means no schema, identity, migration-state, wallet,
journal-mode, or other logical database change. Backend-internal coordination
required to read existing state is permitted.

| Observed state | Outcome after locked recheck |
| --- | --- |
| Empty and unmarked | Bootstrap identity, then migrate |
| Matching, clean, current | Open without schema work |
| Matching, clean, old or no-version | Apply pending forward migrations |
| Populated and unmarked | Reject without durable mutation |
| Foreign or malformed | Reject without durable mutation |
| Matching but dirty | Reject without durable mutation |
| Matching but newer than the binary supports | Reject without mutation |
| Concurrent matching openers | Serialize and converge |
| Concurrent conflicting openers | Winner commits; loser rejects |

For SQLite, empty means no user object. For PostgreSQL, it means the fixed
schema is absent or has no user object and no reserved legacy name exists
elsewhere. Any object in an unmarked fixed schema is populated. An identity
table with no row is malformed, not empty. Legacy or populated-unmarked state
is never adopted automatically.

`Current` means the highest applied version equals the binary's highest
supported schema version. `Old` means the table is empty or holds a lower
positive version. `Newer` means `btcwallet_schema_migrations.version` on SQLite
or `btcwallet.schema_migrations.version` on PostgreSQL exceeds that supported
version. Tuple mismatch includes wrong family, generation, genesis, magic, or
signet digest.

### Atomic initialization

Every candidate that passes preflight repeats the complete classification on
one context-bounded pinned connection in one transaction under native
exclusion:

- SQLite starts the transaction with `BEGIN IMMEDIATE`.
- PostgreSQL begins an explicit transaction-scoped `READ COMMITTED`
  transaction and makes `pg_advisory_xact_lock` its first statement. This does
  not change database, role, session, or runtime Store defaults. The lock is
  local to the current database and released at transaction end.

The PostgreSQL signed bigint lock key is the big-endian two's-complement int64
formed from the first eight bytes of
`SHA256(ASCII("btcwallet-sql-identity-migration"))`:
`-1270285209963246243`.

Initialization then follows this order:

1. Repeat catalog, metadata-shape, tuple, and migration-state classification.
2. Roll back immediately if the result is a rejection case.
3. If empty, create the fixed PostgreSQL schema when applicable, create the
   identity and migration-state relations, and insert the identity row. Leave
   migration state empty.
4. For new or matching-old state, apply only pending forward migrations in
   numeric order and maintain version/dirty state in the same transaction.
5. Commit. Failure rolls back bootstrap, migrations, and migration state.
6. For SQLite only, enable WAL after commit.
7. For both backends, construct Store/sqlc queries, then permit wallet access.

A matching current namespace commits without schema work. Competing openers
wait at the native exclusion, reclassify after the winner, and either converge
on its matching identity or reject its conflicting identity.

## 4. Rationale

Family, generation, and genesis establish application, contract, and chain
ownership. Network magic provides the native protocol discriminator, while the
full signet digest closes its 32-bit collision gap. Named constrained columns
keep the tuple inspectable and atomically comparable. Separate migration state
allows identity meaning to evolve independently of schema progress.

Bitcoin Core similarly combines chain-specific paths with an in-wallet network
marker, keeps wallet schema version separate, and validates at wallet open
rather than on each query. btcwallet retains those principles but needs the
stronger tuple for PostgreSQL and custom signet.

The preflight prevents ordinary rejection from mutating unknown storage. The
locked recheck closes the race between inspection and first write. Keeping both
checks at Store open avoids ongoing wallet-query cost.

## 5. Alternatives Considered

### Path, DSN, genesis, or 32-bit markers only

Paths and DSNs do not survive copying or misconfiguration. Genesis plus network
magic omits schema ownership and cannot distinguish custom signets whose digest
prefixes collide. SQLite `application_id` has the same 32-bit limitation.

### Digest runtime behavior parameters

Network name, address encodings, maturity, HD versions, and coin type do not
identify the owning schema or chain. Binding them would strand valid persisted
data after runtime configuration changes. This decision supersedes provisional
roadmap language that required such a behavior digest.

### Couple identity to migration state or opaque records

Migration version describes schema progress, not ownership. Storing identity in
that row couples different lifecycles. Per-field key/value rows permit partial
identities, while one opaque blob weakens constraints and diagnostics.

### Use only preflight, only locking, or per-query checks

Preflight alone races with another opener. Locking alone enters SQLite's
write-capable path before rejecting known bad input. Per-query checks add
latency after the Store already owns an immutable identity.

### Use process-local locks, manifests, recovery states, or automatic adoption

Process-local locks do not coordinate processes, and sidecars do not fit
PostgreSQL. Manifests and recovery states add a second persistence protocol.
Similar object names do not prove a populated unmarked namespace is safe to
adopt.

## 6. Consequences

### Positive

- Both SQL backends reject wrong-network and foreign storage before mutation.
- Full signet identity cannot alias through truncated network magic.
- PostgreSQL can coexist with lnd while owning an explicit schema.
- Concurrent first openers converge deterministically.
- Identity checks add no ordinary wallet-query latency.

### Negative and Risks

- Manager configuration must preserve the trusted signet challenge digest.
- First PostgreSQL adoption rejects another schema that already uses a reserved
  legacy btcwallet table name.
- Existing unqualified wallets require explicit future conversion.
- Initialization cannot rely on current migration-driver transaction behavior.
- SQLite requires a separate read-only inspection before WAL-backed runtime.

## 7. Implementation Overview

The durable-identity implementation task owns Manager identity input, backend
preflight, constrained metadata, the transaction-aware migration executor, and
SQLite/PostgreSQL tests. Tests cover empty initialization, matching reopen,
wrong network and signet, populated unmarked, malformed, dirty, newer, legacy,
and concurrent matching/conflicting opens.

Store code, SQL schema and migrations, generated output, and migration tests
are deliberately outside this ADR change. Generic locks, manifests, and
recovery machinery remain out of scope.

## 8. References

- [SQLite transactions][sqlite-transactions]
- [SQLite WAL][sqlite-wal]
- [PostgreSQL transaction isolation][pg-isolation]
- [PostgreSQL advisory locks][pg-locks]
- [SQLite Store open path][sqlite-store]
- [SQLite migration path][sqlite-migrations]
- [PostgreSQL Store open path][pg-store]
- [PostgreSQL migration path][pg-migrations]
- [Bitcoin Core file layout][core-files]
- [Bitcoin Core SQLite wallet implementation][core-db]

[sqlite-transactions]: https://www.sqlite.org/lang_transaction.html
[sqlite-wal]: https://www.sqlite.org/wal.html
[pg-isolation]: https://www.postgresql.org/docs/current/transaction-iso.html
[pg-locks]: https://www.postgresql.org/docs/current/explicit-locking.html
[sqlite-store]: ../../../wallet/internal/db/sqlite/store.go
[sqlite-migrations]: ../../../wallet/internal/sql/sqlite/migrations.go
[pg-store]: ../../../wallet/internal/db/pg/store.go
[pg-migrations]: ../../../wallet/internal/sql/pg/migrations.go
[core-files]: https://github.com/bitcoin/bitcoin/blob/master/doc/files.md
[core-db]: https://github.com/bitcoin/bitcoin/blob/master/src/wallet/sqlite.cpp
