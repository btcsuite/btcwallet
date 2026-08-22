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
purpose: names can be renamed, and unnumbered caller-supplied XPub accounts do
not have account numbers.

The word "imported" is overloaded across wallet layers. A wallet may be
imported from a seed while its accounts remain derivable from that seed. An
account XPub may be imported while its child addresses remain derivable from
the XPub. A raw script or public-key address import is not derivable at all.
The SQL schema therefore keeps account-key provenance separate from whether an
address row has derivation identity.

## 2. Decision

Normalize account and address identity around real persisted identity only:

| Case | Parent | Number | Child path |
| --- | --- | --- | --- |
| Wallet-root-derived account | `accounts` row | required | N/A |
| Caller-supplied XPub, unnumbered | `accounts` row | none | N/A |
| Caller-supplied XPub, numbered | `accounts` row | required | N/A |
| Root-derived child address | root account | required | branch/index |
| Unnumbered-XPub child address | caller-supplied account | none | branch/index |
| Numbered-XPub child address | caller-supplied account | required | branch/index |
| Raw imported address | none | none | none; no scope |

The SQL primitive is `is_derived` rather than `is_imported`. An imported-xpub
child address is imported from a user perspective, but it is still derived from
an account xpub and has branch/index path facts. A raw imported address is not
derived from an account and has no scope or path facts.

The address `is_derived` boolean describes row shape only. Account
`is_derived` has the narrower meaning "the account XPub was derived from this
wallet's private root." It is an immutable custody/provenance fact and does not
say whether child addresses can be derived: all three account shapes derive
branch and address children from an account XPub.

### Accounts

`accounts` is the stable account identity table. It holds wallet, scope, name,
account-level public key, master fingerprint, next external/internal derivation
indexes, an `is_derived` provenance bit, and a nullable `account_number`.

Wallet-root-derived accounts set `is_derived` and have a non-null account
number. Unnumbered caller-supplied XPub accounts clear `is_derived` and leave
`account_number` NULL. Numbered caller-supplied XPub accounts also clear
`is_derived`, because the wallet did not derive their account key, but retain
the real non-null hardened account component declared by the caller and
validated against the supplied depth-three XPub.

There is no `derived_accounts` table. The account ID remains an internal Store
identity for all account shapes. It is not a portable public identifier.
Numbered public lookup uses `(scope, account_number)` for either root-derived
or numbered caller-supplied provenance. An unnumbered caller-supplied account
has no number and is selected by its mutable name within its scope.

All numbered accounts in one wallet scope share the same account-number
namespace regardless of provenance. A numbered caller-supplied account
occupies its `(scope, account_number)` slot, and another account that declares
the same pair is rejected. Public-only caller-supplied and wallet-root-derived
accounts cannot coexist under the SQL custody rule, but the numbered namespace
does not acquire a separate caller-supplied domain.

Account provenance, account-number presence and value, master-fingerprint
presence and value, scope, effective address schema, `NoChainSync`, and XPub
are immutable after creation. Account names remain mutable, scope-unique
display and lookup metadata. SQL row IDs and kvdb adapter account numbers never
cross the Store boundary as semantic identity.

#### Account Creation Identity

Wallet-root provenance and account-number presence are orthogonal. The
accepted account shapes are:

| Source | SQL custody | Provenance | Number | Fingerprint |
| --- | --- | --- | --- | --- |
| Generated seed | spendable | wallet-root | required | computed |
| Imported private root | spendable | wallet-root | required | computed |
| Caller-supplied XPub, unnumbered | watch-only | caller-supplied | absent | required |
| Caller-supplied XPub, numbered | watch-only | caller-supplied | required | optional |

The persisted `is_derived` fact and the public `IsImported` projection encode
wallet-root versus caller-supplied provenance. The optional account number
distinguishes unnumbered from numbered caller-supplied identity, so no second
provenance enum is needed. Accounts derived from an imported private wallet
root remain wallet-root-derived; a supplied account XPub remains
caller-supplied even when it has a known account number.

For a numbered caller-supplied XPub, the full key origin is the caller-declared
tuple `(master fingerprint?, purpose', coin_type', account')`. The wallet
validates the public key's network, depth, and hardened account child against
the requested account number. It cannot authenticate the hardened purpose or
coin ancestors or optional fingerprint, which remain caller-declared
provenance. Fingerprint presence, including present-zero, is preserved.
Root-derived accounts use the wallet-computed fingerprint.

#### Account Creation Requests

`NewAccountParams` is the one extensible wallet-owned account-creation request.
It starts with the existing name and scope inputs plus `NoChainSync`. Optional
exact account selection, custom scope schema selection, a supplied account
XPub, and its optional fingerprint enter the request only with their owning
behavior; the initial request does not publish dormant fields. No separate
exact-account, lnd-specific, or key-family operation is introduced.

`AccountInfo` exposes the immutable `NoChainSync` fact alongside the account's
identity facts. This result does not make chain synchronization a custody or
signing signal.

The retained ordinary unnumbered-import signature is
`ImportAccount(context.Context, string, *hdkeychain.ExtendedKey, uint32,
waddrmgr.AddressType, bool) (*AccountInfo, error)`.
Its fingerprint is required, including zero. The XPub version and address type
retain their existing scope and schema selection. The operation has no exact
account number, schema override, or `NoChainSync` input, always creates and
reports `NoChainSync=false`, and does not gain an `ImportAccountParams`
wrapper.

Caller-declared scope is authoritative only for a numbered caller-supplied
XPub request through `NewAccountParams`. Its extended-key version is checked for
the configured Bitcoin network but does not infer scope or schema. Ordinary
`ImportAccount` retains the distinct version-and-address-type selection above.

#### Chain Synchronization

`NoChainSync` is an immutable boolean independent of wallet-level signing
custody:

| Wallet custody | `NoChainSync=false` | `NoChainSync=true` |
| --- | --- | --- |
| Spendable | automatic chain sync | excluded from automatic chain sync |
| Uniformly watch-only | automatic chain sync | excluded from automatic chain sync |

When false, the account participates in automatic chain discovery and live
script registration. When true, its derived scripts are excluded from both.
Neither value changes address ownership, public child derivation, or signing
capability, and neither causes an owned transaction learned through another
ingestion path to be discarded. Signing continues to follow the wallet's
existing custody model.

#### Scope And Branch Schema

An omitted address schema reuses an existing scope's persisted schema or the
canonical schema for a standard scope. Creating a new custom scope requires an
explicit schema. Supplying a schema for an existing scope is an equality
assertion; any external/internal branch mismatch is a conflict and the request
fails before mutation.

Each branch must be derivable from a single account key. The supported forms
are P2PKH (`PubKeyHash`), P2SH-P2WPKH (`NestedWitnessPubKey`), P2WPKH
(`WitnessPubKey`), and key-path P2TR (`TaprootPubKey`); other forms are not
account schemas.

For collision comparison within one wallet, an account XPub's normalized
payload is its public key and chain code. Version bytes, depth, parent
fingerprint, child number, name, optional account number, provenance, and
declared master fingerprint do not distinguish that payload.

Accounts with equal normalized payloads conflict when their corresponding
external branch schemas or corresponding internal branch schemas can derive
the same scripts. External and internal branches are not cross-compared because
their `/0/` and `/1/` derivation paths are disjoint. Admission is allowed only
when both corresponding branch-schema pairs are disjoint. Equal normalized
payloads in one scope always conflict because accounts in that scope share its
effective schema.

Existing schema fields, including `coin_pub_key`, `key_scope_secrets`, and all
other columns, remain. Account-shape constraints and affected validation and
read paths must admit a caller-supplied numbered account with
`is_derived=false` and a non-null `account_number` while preserving the
root-derived numbered and caller-supplied unnumbered shapes.

#### Store Adapter Identity

The shared Store projection needs a stable account selector for each backend,
but that selector is not a public account identity. The internal
`db.AccountInfo.AccountID` field carries the backend adapter's persisted
identity: SQL maps it from `accounts.id`, while kvdb maps it from waddrmgr's
internal account number.

Shared code identifies this adapter value by the `(KeyScope, AccountID)` pair.
kvdb account numbers restart in every key scope, so an `AccountID` can recur
within one wallet. SQL row IDs happen to have wider uniqueness, but shared code
must not depend on that backend-specific property.

kvdb populates the adapter identity for wallet-derived accounts, imported-XPub
accounts, and its imported-address pseudo-account. An imported account has no
public `AccountNumber` under the legacy ordinary-import contract, but waddrmgr
still persists an unmasked internal account number for scoped lookup. Recovery
also uses the adapter identity to key per-account state and stamp scan
horizons. Returning no kvdb adapter identity would therefore make imported-
account recovery and numeric kvdb lookup ambiguous or unusable.

`AccountNumber` remains an optional known hardened account component, and
`AccountName` remains mutable display and lookup metadata. A wallet-derived
kvdb account's adapter ID may numerically equal its account number, but that
coincidence does not give the two fields the same meaning or prove provenance.

The adapter identity is stable only for an account within its backing Store
and backend-defined domain. SQL row IDs and kvdb account numbers are not
comparable, may repeat across key scopes or wallets, and may change during a
backend conversion. They must remain inside Store, recovery, and adapter lookup
boundaries. A wallet-owned public account contract must not expose either
backend's adapter value, an SQL row ID, or the current
`RecoveryState.AccountID` accessor as a portable account ID.

#### Account Alternatives

The first rejected alternative was to keep mapping unnumbered caller-supplied
XPub accounts to account number `0`. That preserves compatibility with
BIP44-shaped callers, but it makes unnumbered imports collide with the default
wallet-derived account and forces runtime code to distinguish fake `0` from
real `0`.

The second rejected alternative was to split BIP44 account numbers into a
`derived_accounts` table. That matched the subtype model, but it mostly moved
one nullable field out of `accounts` while adding another join and a
parent/child shape invariant. A row-local check on `accounts` is simpler and
still prevents unnumbered caller-supplied XPub accounts from being mistaken
for account `0`.

The accepted tradeoff is a nullable `account_number` interpreted together with
immutable account provenance. This keeps the invariant local to the account
row, admits a truthful numbered caller-supplied path, and still removes fake
identity.

#### Account Consequences

Pros:

- Unnumbered caller-supplied XPub accounts can no longer be mistaken for
  account `0`.
- Numbered lookup can represent both root-derived and numbered
  caller-supplied accounts without accepting a backend ID.
- SQL recovery can key unnumbered-XPub scan horizons by immutable internal
  `account_id` while public code uses semantic selectors.
- Account lists remain low-cardinality reads over one identity table.

Cons:

- Go callers must treat account numbers as optional.
- Code handling unnumbered caller-supplied accounts must not collapse SQL NULL
  to Go zero.
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
- Unnumbered-XPub, numbered-XPub, and wallet-root-derived child addresses share
  the same derived-address path model.
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
- The normalized schema applies to the PostgreSQL and SQLite backends. kvdb
  keeps its legacy waddrmgr storage, including the fixed imported account name
  and scoped imported buckets, and only maps legacy rows into the shared Go
  types.
- `db.AccountInfo` exposes an internal adapter `AccountID` and makes
  `AccountNumber` optional. SQL maps `AccountID` from `accounts.id`; kvdb maps
  it from waddrmgr's per-scope internal account number. SQL account numbers are
  present for root-derived and numbered caller-supplied accounts and absent
  for unnumbered caller-supplied accounts. Shared code pairs adapter identity
  with `KeyScope` and must not expose it as a portable public account ID.
- `db.AddressInfo` makes `AccountID` and `AccountNumber` optional. SQL raw
  imports have neither, use an empty account name and zero key scope, and are
  listed with an accountless query. Unnumbered-XPub child addresses have an
  account ID and scope inherited from their account but no account number;
  numbered-XPub children retain their real number.
- `AddressDerivationParams` carries an optional account number. Unnumbered-XPub
  child addresses must not synthesize `0` and accidentally claim a full public
  origin or derive wallet-seed keys. A numbered caller-supplied child may
  report its caller-declared origin without claiming the wallet authenticated
  its hardened ancestors.
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
