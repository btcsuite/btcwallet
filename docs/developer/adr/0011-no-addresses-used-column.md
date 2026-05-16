# ADR 0011: No `used` Column on the Addresses Table

## 1. Context

The wallet needs to answer "has this address ever appeared in a
transaction the wallet has seen?" — a monotonic property used
by the unused-address scan to enforce privacy (never re-offer a
previously-published address).

In the legacy kvdb backend this is a sticky bit on each
managed address (`waddrmgr.ManagedAddress.Used`). It is set
when the wallet observes the address in a tx and never cleared,
even when the underlying credit record is rolled back by a
reorg (wtxmgr deletes credit records on rollback, so the bit
is the wallet's only durable record).

When the SQL backend was first sketched in PR #1162, an
equivalent boolean column was proposed on `addresses`. Review
collapsed it on the grounds of "two sources of truth": the
utxos table already records whether an address has ever
received a credit, so a flag on `addresses` duplicates state.
The conclusion in #1162 was to derive used-ness from the
`utxos` table at read time and drop the column. Issue #1167
captures the orthogonal "unbroadcast tx" privacy gap that
neither approach solves.

A later session reintroduced the column under
`prep-address-manager-store` (PR #1237) along with a trigger
preventing the bit from clearing. The motivation was that the
wallet's unused-address scan needs *monotonic* used-ness —
which the derived query would lose if a reorg deleted the
funding row.

Re-examination of the SQL schema after PR #1232 + ADR 0006
landed makes the picture clear: under the new SQL design, the
reorg-delete concern does not apply.

- `transactions.block_height INTEGER REFERENCES blocks
  (block_height) ON DELETE SET NULL` — a reorged tx becomes
  unconfirmed; the **row stays**. `tx_status` carries the
  validity state as soft deletion.
- `utxos.tx_id BIGINT NOT NULL REFERENCES transactions (id) ON
  DELETE RESTRICT` — the utxo row cannot be deleted while its
  creating transaction exists.
- `utxos.spent_by_tx_id BIGINT REFERENCES transactions (id) ON
  DELETE RESTRICT` — same protection for spent UTXOs.
- Physical removal of records is an explicit pruning operation
  the wallet does not perform in normal flows.

Therefore, on the SQL backend:

```sql
SELECT EXISTS(SELECT 1 FROM utxos WHERE address_id = ?)
```

is **monotonic by construction** through reorgs, replaces,
orphanings, and ordinary operation. The flag column on
`addresses` is genuinely redundant on SQL.

## 2. Decision

The SQL backend (`pg`, `sqlite`) does NOT persist a `used`
column on `addresses`.

- `db.Store.IsUsed` on SQL backends is answered via the derived
  EXISTS query above (projected as part of address-read queries
  for `GetAddress`, `ListAddresses`, etc.).
- `db.Store.MarkAddressUsed` is a **no-op** on SQL backends.
  The wallet's normal "record observed tx" path implicitly
  marks the address used because it inserts the `utxos` row
  that the derived query reads.
- The kvdb backend continues to use waddrmgr's legacy `Used()`
  flag because wtxmgr deletes credit records on reorg and
  cannot provide the monotonic guarantee without a separate
  bit. `db.Store.MarkAddressUsed` on kvdb calls
  `addrStore.MarkUsed(...)` as today.

The `db.AddressInfo.IsUsed` contract field remains. The two
adapters populate it from different sources but with the same
semantics from the wallet's perspective.

## 3. Consequences

### Pros

- Single source of truth on SQL (utxos table), removing the
  drift risk of two booleans encoding the same fact.
- One fewer column, one fewer migration, one fewer trigger,
  one fewer sqlc query. Smaller surface, less migration churn.
- The contract is uniform — wallet code calls
  `w.store.IsUsed(...)` and `w.store.MarkAddressUsed(...)`
  regardless of backend.

### Cons

- The SQL adapter pays a per-row EXISTS sub-query cost on
  address reads. With `idx_utxos_by_address` (defined in
  `000008_utxos.up.sql`) the cost is a bounded index lookup,
  negligible for `GetAddress`-style reads and batchable via
  LEFT JOIN for `ListAddresses`-style scans.
- The asymmetric backend implementation (derived on SQL, flag
  on kvdb) is one more thing for a future contributor to
  understand. Mitigated by:
  1. A schema-level pointer comment in
     `000006_addresses.up.sql` next to where someone would
     consider adding the column.
  2. Doc comments on `db.Store.IsUsed` and
     `db.Store.MarkAddressUsed` that explain the asymmetric
     implementation and point here.

### Orthogonal: the unbroadcast-tx gap

Neither design closes the case where a user constructs (but
does not broadcast) a tx referencing a fresh address. The
wallet sees no utxos record and no flag set, so the address
remains "unused" and can be re-offered. This is issue #1167
and is independent of where used-ness is stored.

### Future: if kvdb ever survives reorgs

If wtxmgr's destructive-rollback behavior is ever changed (so
credit records survive reorg the way SQL records do), the
kvdb-side flag becomes redundant for the same reason. At that
point the `MarkAddressUsed` contract method could be retired
entirely. That is out of scope here and would be a future ADR.

## 4. Implementation notes

- Migration `000011_addresses_used.up.sql` and its down-sql
  variant are deleted from both `pg` and `sqlite` migration
  directories.
- The sqlc `MarkAddressUsed` query is removed from
  `wallet/internal/sql/pg/queries/addresses.sql` and the
  sqlite mirror.
- Address-read queries project `is_used` via
  `EXISTS(SELECT 1 FROM utxos AS u WHERE u.address_id = a.id)`
  instead of `a.used`.
- pg/sqlite adapter `Store.MarkAddressUsed` returns `nil`; doc
  comment cites this ADR.
- kvdb adapter unchanged.
- Wallet code (the `addresses-used-flag` side branch) keeps
  the contract-level routing.

## 5. References

- PR #1162 discussion that first removed the flag
  (`wallet/internal/db/data_types.go`,
  `wallet/internal/db/migrations/postgres/000006_addresses.up.sql`
  threads on the merged PR).
- PR #1237 thread that reopened the question.
- ADR 0006 — the soft-delete / ON DELETE RESTRICT schema
  decisions that make the SQL derivation monotonic.
- Issue #1167 — orthogonal unbroadcast-tx privacy gap.
