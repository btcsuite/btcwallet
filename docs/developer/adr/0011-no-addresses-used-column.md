# ADR 0011: No `used` Column on the Addresses Table

## 1. Context

The wallet needs to know whether an address has appeared in any transaction that
the wallet saw. This property is monotonic. Unused-address scans use this
property so that the wallet does not offer a previously published address
again.

The SQL transaction schema keeps observed wallet history as the source of
truth. The schema has these properties:

- A transaction that is disconnected from the best chain stays in the
  `transactions` table. The wallet updates its status and block metadata.
- `utxos` rows reference their creating transaction with restrictive foreign
  keys.
- During normal reorg, replace, or orphan handling, the wallet does not
  physically remove these rows.

Observed credits stay in the SQL history. Thus, the wallet can derive address
used-ness from transaction state:

```sql
SELECT EXISTS(SELECT 1 FROM utxos WHERE address_id = ?)
```

A second, stored `addresses.used` flag would duplicate the same fact. The
duplicate would also create a risk of drift between address metadata and wallet
history.

### Scope

The SQL `is_used` projection is monotonic for non-abandoned wallet history.
Explicit abandon/delete flows intentionally remove the abandoned transaction
state. This matches the rest of the wallet's abandon semantics: balances revert
and the corresponding change indices may become reusable.

## 2. Decision

The SQL backends (`pg` and `sqlite`) do not persist a `used` column on the
`addresses` table.

- SQL address-read queries project `db.AddressInfo.IsUsed` from `EXISTS` over
  `utxos`.
- The Store interface intentionally has no SQL `MarkAddressUsed` method. When
  the wallet records an observed wallet transaction, it inserts the `utxos` row.
  Future address reads consult that row through the `EXISTS` projection.
- The kvdb backend continues to populate `IsUsed` from waddrmgr's sticky used
  bit. The reason is that legacy rollback handling does not provide the same
  durable SQL history table.

The `db.AddressInfo.IsUsed` contract stays backend-neutral. Callers see the
same logical wallet property. SQL derives the property from wallet history, and
kvdb reads the property from legacy address metadata.

## 3. Consequences

### Pros

- SQL has one source of truth for observed address used-ness.
- Address metadata does not need an extra column, migration, trigger, or write
  path.
- Wallet code can continue to call the Store contract. Wallet code does not
  need to know how each backend materializes `IsUsed`.

### Cons

- SQL address reads pay the cost of an `EXISTS` lookup against `utxos`. The
  `idx_utxos_by_address` index bounds that cost for single-address reads and
  address-list scans.
- The SQL and kvdb adapters implement the same contract differently. Store
  method comments and schema comments should point to this ADR. Then the
  asymmetry stays intentional and discoverable.

### Orthogonal: the unbroadcast-tx gap

Neither a derived SQL projection nor a stored flag covers one case: a
transaction that the user constructs but never records or broadcasts. If no
wallet transaction state exists, the wallet has no durable fact that proves
the address was published. That privacy gap is independent of where the
used-ness is materialized.

## 4. Implementation Notes

- SQL migrations do not add an `addresses.used` column.
- SQL address-read queries project `is_used` with `EXISTS` over `utxos`. The
  queries do not read address metadata for this property.
- The Store interface has no `MarkAddressUsed` method on SQL backends. SQL
  derives used-ness from wallet transaction state that is recorded in the
  `utxos` table.
- The kvdb adapter continues to use waddrmgr's used bit.
