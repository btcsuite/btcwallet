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
btcwallet role wallet or to the requested Bitcoin network. Before wallet
access, Store startup rejects populated unmarked storage or a mismatched
identity.

SQLite owns a complete database file. PostgreSQL owns the fixed `btcwallet`
schema within a database. That database may also contain lnd or other
application data.

## 2. Context

The current SQLite path enables WAL before it constructs a migration driver.
That migration driver may create its default migration table. The PostgreSQL
path creates its default migration table and wallet objects through the
ambient `search_path`.
Neither path validates durable ownership before mutation.

### Constraints

- Identity must be validated before persistent pragmas, migration metadata,
  migrations, sqlc queries, or wallet access can mutate the namespace.
- Only an empty unmarked SQLite file or an absent PostgreSQL `btcwallet` schema
  is adoptable. Other unmarked storage requires a separate conversion.
- One Manager owns a database. Store startup checks identity once. Ordinary
  wallet queries do not check identity.
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
from `Hash.String()`. PostgreSQL stores network magic in `BIGINT` to preserve
the full unsigned uint32 value. Comparisons are exact and byte-for-byte.

The identity excludes these values:

- `Params.Name`
- coinbase maturity
- address and WIF prefixes
- Bech32 HRP
- HD private and public versions
- BIP44 coin type

Those values affect presentation, policy, import/export, or per-wallet and
per-scope behavior. Their existing subsystems remain responsible for them.

### Signet identity

All signets share one genesis block. Network magic contains only four bytes of
the challenge digest. The full identity input is:

```text
DoubleSHA256(byte(len(challenge)) || challenge)
```

This formula is the one-byte-length-prefixed serialization that
`chaincfg.CustomSignetParams` uses. Manager configuration must carry the
trusted 32-byte result in returned array order. The result must come from the
same challenge that was used to construct those params. Before database
access, the little-endian uint32 from the first four bytes of the result must
equal `uint32(Params.Net)`.

A network with the fixed signet genesis is signet regardless of `Params.Name`.
A signet network requires the digest. A non-signet network requires NULL.
Missing or internally inconsistent input is rejected before database access.
A stored identity with equal magic and a different challenge is rejected
during startup before mutation.

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
magic, so PostgreSQL preserves every unsigned 32-bit value.

Startup validates the readable column shape and the current singleton values.
Startup does not validate the exact catalog definition of every bootstrap
constraint.

Startup requires exactly one readable row, selected by `id = 1`, with matching
identity values. Startup rejects zero or multiple rows, unreadable columns, and
mismatched values.

Ordinary migration state remains separate, and golang-migrate owns it. Identity
commits before migrations run. Migration progress does not change identity.

### Startup gate

Store startup validates the requested identity before connection setup. After
open, one short transaction initializes empty storage or compares its
singleton. Populated unmarked storage and every mismatch make startup fail.
Startup then returns no Store.

After identity commits, SQLite enables WAL, and each backend runs the existing
migrations. Store construction and wallet access begin only after migrations.
Ordinary wallet operations do not recheck identity.

## 4. Rationale

The fixed table name and genesis establish application and chain ownership.
Network magic provides the native protocol discriminator. The full signet
digest closes the 32-bit collision gap of network magic. Separate migration
state keeps schema progress independent from identity.

Bitcoin Core uses similar principles:

- Bitcoin Core combines chain-specific paths with an in-wallet network marker.
- Bitcoin Core keeps the wallet schema version separate.
- Bitcoin Core validates at wallet open, not on each query.

btcwallet keeps those principles but needs the stronger tuple for PostgreSQL
and custom signet.

The startup transaction initializes or compares identity before normal
database work. A check only at Store open avoids ongoing wallet-query cost.

## 5. Alternatives Considered

### Path, DSN, genesis, or 32-bit markers only

Paths and DSNs do not survive copying or misconfiguration. Genesis plus network
magic cannot distinguish custom signets whose digest prefixes collide. SQLite
`application_id` has the same 32-bit limitation.

### Digest runtime behavior parameters

Network name, address encodings, maturity, HD versions, and coin type do not
identify the owning schema or chain. If identity binds these values, valid
persisted data becomes stranded after runtime configuration changes. Therefore,
no behavior digest is persisted.

### Couple identity to migration state or opaque records

Migration version describes schema progress, not ownership. Identity stored in
that row couples different lifecycles. Per-field key/value rows permit partial
identities. One opaque blob weakens constraints and diagnostics.

### Per-query checks or simultaneous Managers

Per-query checks add latency after Store startup establishes identity.
Running simultaneous Managers against one database is unsupported.

### Use manifests, recovery states, or automatic adoption

Manifests and recovery states add a second persistence protocol. Similar object
names do not prove that a populated unmarked namespace is safe to adopt.

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
existing migrations. Backend tests cover initialization, matching reopen,
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
