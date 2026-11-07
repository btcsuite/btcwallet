# ADR 0011: No `used` Column on the Addresses Table

## 1. Context

The wallet needs to answer whether an address has appeared in any transaction
the wallet has seen. This is a monotonic property used by unused-address scans
to avoid re-offering a previously published address.

The SQL transaction schema keeps observed wallet history as the source of
truth. A transaction that is disconnected from the best chain remains in the
`transactions` table with updated status and block metadata, and `utxos` rows
reference their creating transaction with restrictive foreign keys. The wallet
does not physically remove these rows during normal reorg, replace, or orphan
handling.

Because observed credits remain represented in SQL history, address used-ness
can be derived from transaction state:

```sql
SELECT EXISTS(SELECT 1 FROM utxos WHERE address_id = ?)
```

Storing a second `addresses.used` flag would duplicate the same fact and create
drift risk between address metadata and wallet history.

### Scope

The SQL `is_used` projection is monotonic for non-abandoned wallet history.
Explicit abandon/delete flows intentionally remove the abandoned transaction
state, matching the rest of the wallet's abandon semantics: balances revert and
the corresponding change indices may become reusable.

## 2. Decision

The SQL backends (`pg` and `sqlite`) do not persist a `used` column on the
`addresses` table.

- SQL address-read queries project `db.AddressInfo.IsUsed` from `EXISTS` over
  `utxos`.
- The Store interface intentionally has no SQL `MarkAddressUsed` method:
  recording an observed wallet transaction inserts the `utxos` row that future
  address reads consult via the `EXISTS` projection.
- The kvdb backend continues to populate `IsUsed` from waddrmgr's sticky used
  bit, because legacy rollback handling does not provide the same durable SQL
  history table.

The `db.AddressInfo.IsUsed` contract remains backend-neutral. Callers see the
same logical wallet property even though SQL derives it from wallet history and
kvdb reads it from legacy address metadata.

## 3. Consequences

### Pros

- SQL has one source of truth for observed address usage.
- Address metadata avoids an extra column, migration, trigger, and write path.
- Wallet code can continue to call the Store contract without knowing how each
  backend materializes `IsUsed`.

### Cons

- SQL address reads pay an `EXISTS` lookup against `utxos`. The
  `idx_utxos_by_address` index bounds that cost for single-address reads and
  address-list scans.
- The SQL and kvdb adapters implement the same contract differently. Store
  method comments and schema comments should point to this ADR so the asymmetry
  remains intentional and discoverable.

### Orthogonal: the unbroadcast-tx gap

Neither a derived SQL projection nor a stored flag covers a transaction the
user constructs but never records or broadcasts. If no wallet transaction state
exists, the wallet has no durable fact proving the address was published. That
privacy gap is independent of where used-ness is materialized.

## 4. Implementation Notes

- SQL migrations do not add an `addresses.used` column.
- SQL address-read queries project `is_used` with `EXISTS` over `utxos` instead
  of reading address metadata.
- The Store interface has no `MarkAddressUsed` method on SQL backends; SQL
  derives used-ness from wallet transaction state recorded in the `utxos`
  table.
- The kvdb adapter keeps using waddrmgr's used bit.
