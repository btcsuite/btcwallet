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

The recovery follow-up needs an immutable SQL identity for imported xpub scan
horizons. Account names and nullable account numbers are not suitable for that
purpose: names can be renamed, and imported xpubs do not have BIP44 account
numbers.

## 2. Decision

Normalize account and address identity into parent identity tables plus subtype
tables:

- `accounts` is the stable HD-account identity table. It holds shared account
  metadata: wallet, scope, name, account-level public key, master fingerprint,
  and next external/internal derivation indexes.
- `derived_accounts` stores only wallet-derived BIP44 account numbers. Imported
  xpub accounts are `accounts` rows with no `derived_accounts` child.
- `addresses` is the stable address identity table. It holds wallet, scope,
  script pubkey, script type, creation time, imported public key material, and a
  structural `is_derived` bit.
- `derived_addresses` stores HD child ownership and path data: account ID,
  branch, and index. Raw imported addresses are `addresses` rows with no
  `derived_addresses` child.

The parent tables carry structural booleans:

- `accounts.is_derived` says whether the account should have a
  `derived_accounts` child.
- `addresses.is_derived` says whether the address should have a
  `derived_addresses` child.

These booleans describe table shape only. They are not provenance or audit
fields. If provenance becomes necessary later, it should be modeled separately.

The store enforces parent/child consistency through its write workflow,
database triggers, and read-time corruption checks. Parent account and address
identity fields, including `id`, `wallet_id`, `scope_id`, and `is_derived`, are
immutable after creation. Derived child rows are insert-only because their
account number, account ownership, and address path data are structural identity
facts. Child tables do not duplicate the structural booleans solely to enable
composite foreign keys.

The reserved name `imported` remains a user-facing compatibility alias for raw
imported addresses. It is not materialized as an SQL account row. APIs that list
addresses, filter UTXOs, or compute balances for `imported` use raw-import query
variants instead of routing through account lookup.

## 3. Consequences

### Pros

- Imported xpub accounts can no longer be mistaken for BIP44 account `0`.
- `GetAccountByNumber` is derived-account-only by construction.
- SQL recovery can later key imported-xpub scan horizons by immutable
  `account_id`.
- Raw imported addresses no longer require a fake account row.
- Account-name uniqueness stays centralized on `accounts`.
- Address and UTXO hot paths can start from selective indexed tables instead of
  parent tables with broad optional filters.

### Cons

- SQL reads need additional joins and generated query churn.
- Go callers must treat account numbers as optional where imported xpub accounts
  or raw imported addresses can appear.
- Every account/address read path must use the same corruption checks so a
  parent/child shape mismatch fails loudly instead of leaking through one query.
- Raw-import compatibility paths are explicit query variants, not ordinary
  account queries.

## 4. Implementation Notes

- Modify the existing unmerged account and address migrations in place. Do not
  add new migration numbers for this feature-branch schema rewrite.
- `db.AccountInfo` exposes SQL `AccountID` and makes `AccountNumber` optional.
  The kvdb backend leaves `AccountID` nil.
- `db.AddressInfo` makes `AccountID` and `AccountNumber` optional. Raw imports
  have neither; imported-xpub child addresses have an account ID but no BIP44
  account number.
- `AddressDerivationParams` carries an optional derived account number. Imported
  xpub child addresses must not synthesize `0` and accidentally derive wallet
  seed keys.
- Low-cardinality account lists may start from `accounts` and batch-hydrate
  subtype data. Address, UTXO, and balance reads must reject or exclude malformed
  parent/child shapes instead of silently reclassifying corrupt rows.

## 5. References

- [ADR 0006](0006-wtxmgr-sql-schema.md): SQL transaction schema.
- [ADR 0011](0011-no-addresses-used-column.md): SQL derives address used-ness
  from wallet transaction state.
- [ADR 0012](0012-wallet-level-watch-only-uniformity.md): wallet-level
  watch-only invariant. This ADR supersedes its SQL imported-address bucket
  shape: raw imports now use the reserved name only as an alias, not as a stored
  account row.
