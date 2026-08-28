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
btcwallet role wallet or the requested Bitcoin network. Store startup rejects
populated unmarked storage or mismatched identity before wallet access.

SQLite owns a complete database file. PostgreSQL owns the fixed `btcwallet`
schema within a database that may also contain lnd or other application data.

## 2. Context

The current SQLite path enables WAL before constructing a migration driver,
which may create its default migration table. The PostgreSQL path creates its
default migration table and wallet objects through the ambient `search_path`.
Neither path validates durable ownership before mutation.

### Constraints

- Identity must be validated before persistent pragmas, migration metadata,
  migrations, sqlc queries, or wallet access can mutate the namespace.
- Only an empty unmarked SQLite file or an absent PostgreSQL `btcwallet` schema
  is adoptable. Other unmarked storage requires a separate conversion.
- One Manager owns a database. Store startup checks identity once; ordinary
  wallet queries do not.
- Identity is independent of ordinary migration progress and runtime wallet
  parameters.
- Existing golang-migrate paths run only after identity succeeds.

## 3. Decision

### Identity contract

Every role-wallet SQL namespace contains exactly one immutable identity row:

| Field | Required value and encoding |
| --- | --- |
| `genesis_hash` | Exact 32 bytes from `chaincfg.Params.GenesisHash[:]` |
| `network_magic` | Mathematical unsigned 32-bit `Params.Net` value |
| `signet_challenge_digest` | Trusted 32-byte signet digest; NULL otherwise |

Genesis bytes use `chainhash.Hash` array order, not the reversed display order
from `Hash.String()`. PostgreSQL stores network magic in `BIGINT`, preserving
the full unsigned uint32 value. Comparisons are exact and byte-for-byte.

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
equal-magic/different-challenge stored identity is rejected during startup
before mutation.

### Metadata ownership

PostgreSQL stores every role-wallet object in schema `btcwallet` and never
depends on the ambient `search_path`. SQLite treats the complete file as its
namespace. Their identity tables are:

| Backend | Identity table |
| --- | --- |
| SQLite | `btcwallet_database_identity` |
| PostgreSQL | `btcwallet.database_identity` |

The columns are `id`, `genesis_hash`, `network_magic`, and
`signet_challenge_digest`. `id` is the primary key, constrained to 1. Integer
and byte fields enforce their ranges and lengths. PostgreSQL uses `BIGINT` for
magic so every unsigned 32-bit value is preserved.

Startup requires exactly one readable row selected by `id = 1` whose identity
values match. Zero or multiple rows, unreadable columns, and mismatched values
are rejected.

Ordinary migration state remains separate and owned by golang-migrate. Identity
commits before migrations run and is not changed by migration progress.

### Startup gate

Store startup validates requested identity before connection setup. After open,
one short transaction initializes empty storage or compares its singleton.
Populated unmarked storage and every mismatch reject startup without returning
a Store.

After identity commits, SQLite enables WAL and each backend runs existing
migrations. Store construction and wallet access begin only after migrations;
ordinary wallet operations do not recheck identity.

## 4. Rationale

The fixed table name and genesis establish application and chain ownership.
Network magic provides the native protocol discriminator, while the full
signet digest closes its 32-bit collision gap. Separate migration state keeps
schema progress independent from identity.

Bitcoin Core similarly combines chain-specific paths with an in-wallet network
marker, keeps wallet schema version separate, and validates at wallet open
rather than on each query. btcwallet retains those principles but needs the
stronger tuple for PostgreSQL and custom signet.

The startup transaction initializes or compares identity before normal
database work. Checking only at Store open avoids ongoing wallet-query cost.

## 5. Alternatives Considered

### Path, DSN, genesis, or 32-bit markers only

Paths and DSNs do not survive copying or misconfiguration. Genesis plus network
magic cannot distinguish custom signets whose digest prefixes collide. SQLite
`application_id` has the same 32-bit limitation.

### Digest runtime behavior parameters

Network name, address encodings, maturity, HD versions, and coin type do not
identify the owning schema or chain. Binding them would strand valid persisted
data after runtime configuration changes, so no behavior digest is persisted.

### Couple identity to migration state or opaque records

Migration version describes schema progress, not ownership. Storing identity in
that row couples different lifecycles. Per-field key/value rows permit partial
identities, while one opaque blob weakens constraints and diagnostics.

### Per-query checks or simultaneous Managers

Per-query checks add latency after Store startup establishes identity.
Running simultaneous Managers against one database is unsupported.

### Use manifests, recovery states, or automatic adoption

Manifests and recovery states add a second persistence protocol. Similar object
names do not prove a populated unmarked namespace is safe to adopt.

## 6. Consequences

### Positive

- Both SQL backends reject wrong-network and foreign storage before mutation.
- Full signet identity cannot alias through truncated network magic.
- PostgreSQL can coexist with lnd while owning an explicit schema.
- Identity checks add no ordinary wallet-query latency.

### Negative and Risks

- Manager configuration must preserve the trusted signet challenge digest.
- A pre-existing unmarked PostgreSQL `btcwallet` schema is not adopted.
- Simultaneous Managers targeting one database are unsupported.

## 7. Implementation Overview

Manager constructs one identity for the selected SQL Store. Checked SQL defines
metadata and generated row operations. Each backend gates startup before its
existing migrations; backend tests cover initialization, matching reopen,
mismatches, and populated unmarked storage.

## 8. References

- [SQLite transactions][sqlite-transactions]
- [SQLite WAL][sqlite-wal]
- [SQLite Store open path][sqlite-store]
- [SQLite migration path][sqlite-migrations]
- [PostgreSQL Store open path][pg-store]
- [PostgreSQL migration path][pg-migrations]
- [Bitcoin Core file layout][core-files]
- [Bitcoin Core SQLite wallet implementation][core-db]

[sqlite-transactions]: https://www.sqlite.org/lang_transaction.html
[sqlite-wal]: https://www.sqlite.org/wal.html
[sqlite-store]: ../../../wallet/internal/db/sqlite/store.go
[sqlite-migrations]: ../../../wallet/internal/sql/sqlite/migrations.go
[pg-store]: ../../../wallet/internal/db/pg/store.go
[pg-migrations]: ../../../wallet/internal/sql/pg/migrations.go
[core-files]: https://github.com/bitcoin/bitcoin/blob/master/doc/files.md
[core-db]: https://github.com/bitcoin/bitcoin/blob/master/src/wallet/sqlite.cpp
