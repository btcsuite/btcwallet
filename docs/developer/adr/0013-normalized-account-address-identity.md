# ADR 0013: Normalized Account and Address Identity

## 1. Context

The SQL wallet store originally modeled account and address variants by mixing
shared identity columns with nullable subtype columns:

- `accounts.account_number` was nullable so imported xpub accounts could live in
  the same table as wallet-derived BIP44 accounts.
- `addresses.account_id` was required, so raw imported addresses had to live
  under a reserved account named `imported` even though they are not account
  children in the HD derivation tree.
- `addresses.address_branch` and `addresses.address_index` were nullable so
  raw imports could live beside derived addresses.

That shape caused the store to carry fake identity. Imported xpub accounts could
be accidentally interpreted as account number `0`, and raw imported addresses
looked like members of an account solely because SQL needed a non-null
`account_id`.

The recovery follow-up needs immutable SQL identity for imported xpub scan
horizons. Account names and nullable account numbers are not suitable for that
purpose: names can be renamed, and imported xpubs do not have BIP44 account
numbers.

The word "imported" is overloaded across wallet layers. A wallet may be
imported from a seed while its accounts remain derivable from that seed. An
account xpub may be imported while its child addresses remain derivable from the
xpub. A raw script or public-key address import is not derivable at all. The SQL
schema therefore models whether a row has derivation identity, not where the
user originally obtained the material.

## 2. Decision

Normalize account and address identity around real persisted identity only:

| Case | Parent | Number | Path |
| --- | --- | --- | --- |
| Wallet-derived account | `accounts` row | BIP44 number | N/A |
| Imported xpub account | `accounts` row | none | N/A |
| Wallet-derived child address | derived account | has number | branch/index |
| Imported-xpub child address | imported xpub account | none | branch/index |
| Raw imported address | none | none | none; no scope |

The SQL primitive is `is_derived` rather than `is_imported`. An imported-xpub
child address is imported from a user perspective, but it is still derived from
an account xpub and has branch/index path facts. A raw imported address is not
derived from an account and has no scope or path facts.

The structural booleans describe row shape only. They are not provenance or
audit fields. If provenance becomes necessary later, it should be modeled
separately.

### Accounts

`accounts` is the stable account identity table. It holds wallet, scope, name,
account-level public key, master fingerprint, next external/internal derivation
indexes, a structural `is_derived` bit, and a nullable `account_number`.

Wallet-derived accounts set `is_derived` and have a non-null BIP44 account
number. Imported xpub accounts clear `is_derived` and leave `account_number`
NULL because they do not have wallet-derived BIP44 identity.

There is no `derived_accounts` table. The account ID is the immutable identity
for both wallet-derived accounts and imported xpub accounts. Account number is
an optional identity attribute of wallet-derived accounts only.

Account identity fields, including `id`, `wallet_id`, `scope_id`,
`is_derived`, and `account_number`, are immutable after creation. Account-name
uniqueness stays centralized on `accounts`.

#### Account Alternatives

The first rejected alternative was to keep mapping imported xpub accounts to
account number `0`. That preserves compatibility with BIP44-shaped callers, but
it makes imported xpubs collide with the default wallet-derived account and
forces runtime code to distinguish fake `0` from real `0`.

The second rejected alternative was to split BIP44 account numbers into a
`derived_accounts` table. That matched the subtype model, but it mostly moved
one nullable field out of `accounts` while adding another join and a
parent/child shape invariant. A row-local check on `accounts` is simpler and
still prevents imported xpub accounts from being mistaken for BIP44 account
`0`.

The accepted tradeoff is a nullable `account_number` with `is_derived` enforcing
the row shape. This keeps the account invariant local to the account row, avoids
parent/child drift for one optional field, and still removes fake identity.

#### Account Consequences

Pros:

- Imported xpub accounts can no longer be mistaken for BIP44 account `0`.
- `GetAccountByNumber` is derived-account-only by construction.
- SQL recovery can later key imported-xpub scan horizons by immutable
  `account_id`.
- Account lists remain low-cardinality reads over one identity table.

Cons:

- Go callers must treat account numbers as optional.
- Imported account code must not collapse SQL NULL to Go zero.
- Read paths must consistently reject impossible account shapes.

### Addresses

`addresses` is the stable wallet-local script identity table. It holds wallet,
script pubkey, script type, creation time, imported public-key material, and a
structural `is_derived` bit. It does not store scope, account, branch, or index.

`derived_addresses` stores HD child ownership and path data: wallet ID, account
ID, branch, and index. Derived address scope is inherited through the owning
account:

```text
derived_addresses.account_id -> accounts.scope_id
```

Raw imported addresses are `addresses` rows with no `derived_addresses` child.
They have no account, no scope, no branch, and no index.

The reserved name `imported` remains a user-facing compatibility alias for raw
imported addresses. It is not materialized as an SQL account row. APIs that list
raw imported addresses use an accountless query where both `Scope` and
`AccountName` are unset. UTXO and balance filters do not have a raw-import-only
SQL selector: nil filters mean whole wallet, while account filters match real
accounts only.

Address identity fields, including `id`, `wallet_id`, and `is_derived`, are
immutable after creation. `derived_addresses` rows are insert-only because their
account ownership and address path data are structural identity facts.

#### Address Alternatives

The first rejected alternative was to store raw imported addresses under an SQL
account named `imported`. ADR 0012 chose that bucket shape for the earlier
watch-only decision, but this identity decision rejects it for SQL because it
gives raw imports fake account and scope identity. The reserved name remains
only as a wallet-facing alias.

The second rejected alternative was to keep nullable `account_id`,
`address_branch`, and `address_index` columns on `addresses`. That would make
the derived/raw invariant row-local, but it would also make the base address
table carry HD path columns that are meaningless for raw imports.

The accepted tradeoff is a `derived_addresses` subtype table. It adds a join
and requires consistent shape checks, but it keeps raw imports as wallet-local
script identity only and lets derived-address indexes start from account/path
facts.

#### Address Consequences

Pros:

- Raw imported addresses no longer require a fake account row.
- Raw imports no longer carry fake scope or derivation-path identity.
- Imported-xpub child addresses and wallet-derived child addresses share the
  same derived-address path model.
- Derived address queries can start from account/path facts, while raw import
  queries can start from wallet-local script identity.
- Account-scoped address creation and address-index checks can use
  `derived_addresses(account_id, branch, index)` without scanning raw imports.
- Script and UTXO reads can join to derived-path metadata only when callers need
  account ownership, leaving raw imports anchored by wallet/script identity.

Cons:

- Address reads need additional joins and generated query churn.
- Write workflows and database constraints own parent/child shape validation;
  read paths should not duplicate those checks on UTXO and balance queries.
- Raw-import compatibility paths must not rely on a scoped SQL account alias.

## 3. Implementation Notes

- Modify the existing unmerged account and address migrations in place. Do not
  add new migration numbers for this feature-branch schema rewrite.
- The normalized schema applies to the PostgreSQL and SQLite backends. kvdb keeps
  its legacy waddrmgr storage, including the fixed imported account name and
  scoped imported buckets, and only maps legacy rows into the shared Go types.
- `db.AccountInfo` exposes SQL `AccountID` and makes `AccountNumber` optional.
  The kvdb backend leaves `AccountID` nil.
- `db.AddressInfo` makes `AccountID` and `AccountNumber` optional. SQL raw
  imports have neither, use an empty account name and zero key scope, and are
  listed with an accountless query. Imported-xpub child addresses have an account
  ID and scope inherited from their account but no BIP44 account number.
- `AddressDerivationParams` carries an optional derived account number. Imported
  xpub child addresses must not synthesize `0` and accidentally derive wallet
  seed keys.
- `ListAddressesQuery` uses pointer selectors: both `Scope` and `AccountName`
  set means account-scoped derived children; both nil means raw imported
  addresses; one set without the other is invalid.
- `ListUTXOs` account filters match real accounts only. A nil account filter is
  wallet-wide and includes raw imports, so higher layers that expose the
  reserved imported alias must filter accountless raw-import UTXOs locally.
- Low-cardinality account lists may start from `accounts`. Derived address reads
  can start from account/path data, while raw imported address reads can start
  from wallet-local script identity.

## 4. References

- [ADR 0006](0006-wtxmgr-sql-schema.md): SQL transaction schema.
- [ADR 0011](0011-no-addresses-used-column.md): SQL derives address used-ness
  from wallet transaction state.
- [ADR 0012](0012-wallet-level-watch-only-uniformity.md): wallet-level
  watch-only invariant. This ADR supersedes its SQL imported-address bucket
  shape: raw imports now use the reserved name only as an alias, not as a stored
  account row.
