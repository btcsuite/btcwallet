# ADR 0013: Normalized Account and Address Identity

## 1. Context

The SQL wallet store first modeled account and address variants with a mix of
shared identity columns and nullable subtype columns:

- `accounts.account_number` was nullable so imported xpub accounts could be in
  the same table as wallet-derived BIP44 accounts.
- `addresses.account_id` was required. Thus raw imported addresses had to be
  under a reserved account named `imported`, although they are not account
  children in the HD derivation tree.
- `addresses.address_branch` and `addresses.address_index` were nullable so
  raw imports could be beside derived addresses.

Because of that shape, the store carried fake identity. Imported xpub accounts
could be accidentally interpreted as account number `0`. Raw imported addresses
looked like members of an account only because SQL needed a non-null
`account_id`.

The recovery follow-up needs an immutable SQL identity for imported xpub scan
horizons. Account names and nullable account numbers are not suitable for that
purpose. Names can be renamed. Unnumbered caller-supplied XPub accounts do not
have account numbers.

The word "imported" has more than one meaning across wallet layers:

- A wallet may be imported from a seed while its accounts remain derivable
  from that seed.
- An account XPub may be imported while its child addresses remain derivable
  from the XPub.
- A raw script or public-key address import is not derivable at all.

Thus the SQL schema keeps account-key provenance separate from whether an
address row has derivation identity.

## 2. Decision

Normalize account and address identity so that it uses only real persisted
identity:

| Case | Parent | Number | Child path |
| --- | --- | --- | --- |
| Wallet-root-derived account | `accounts` row | required | N/A |
| Caller-supplied XPub, unnumbered | `accounts` row | none | N/A |
| Caller-supplied XPub, numbered | `accounts` row | required | N/A |
| Root-derived child address | root account | required | branch/index |
| Unnumbered-XPub child address | caller-supplied account | none | branch/index |
| Numbered-XPub child address | caller-supplied account | required | branch/index |
| Raw imported address | none | none | none; no scope |

The SQL primitive is `is_derived`, not `is_imported`. From the user
perspective, an imported-xpub child address is imported. But the address is
still derived from an account xpub and has branch/index path facts. A raw
imported address is not derived from an account and has no scope or path facts.

The address `is_derived` boolean describes row shape only. The account
`is_derived` boolean has the narrower meaning "the account XPub was derived
from this wallet's private root." The account `is_derived` boolean is an
immutable custody/provenance fact. It does not tell whether child addresses can
be derived. All three account shapes derive branch and address children from an
account XPub.

### Accounts

`accounts` is the stable account identity table. It holds these fields:

- wallet
- scope
- name
- account-level public key
- master fingerprint
- next external/internal derivation indexes
- an `is_derived` provenance bit
- a nullable `account_number`

Wallet-root-derived accounts set `is_derived` and have a non-null account
number. Unnumbered caller-supplied XPub accounts clear `is_derived` and leave
`account_number` NULL. Numbered caller-supplied XPub accounts also clear
`is_derived`, because the wallet did not derive their account key. But these
accounts keep the real non-null hardened account component that the supplied
depth-three XPub encodes.

There is no `derived_accounts` table. The account ID remains an internal Store
identity for all account shapes. The account ID is not a portable public
identifier. A numbered public lookup uses `(scope, account_number)` for
root-derived provenance and for numbered caller-supplied provenance. An
unnumbered caller-supplied account has no number. Lookup selects it by its
mutable name within its scope.

All numbered accounts in one wallet scope share the same account-number
namespace, whatever their provenance. A numbered caller-supplied account
occupies its `(scope, account_number)` slot. Another account that declares the
same pair is rejected. Wallet-root-derived and caller-supplied accounts may
coexist under the custody policy in
[ADR 0012](0012-wallet-level-watch-only-uniformity.md).
The numbered namespace does not get a separate caller-supplied domain.

These account facts are immutable after creation:

- account provenance
- account-number presence and value
- master-fingerprint presence and value
- scope
- effective address schema
- `NoChainSync`
- XPub

Account names remain mutable. They are scope-unique metadata for display and
lookup. SQL row IDs and kvdb adapter account numbers never cross the Store
boundary as semantic identity.

#### Account Creation Identity

Two facts are separate: whether the account key was imported, and whether its
account number is known. The supported account shapes are:

| Source | Account custody | Account key | Number | Fingerprint |
| --- | --- | --- | --- | --- |
| Generated seed | spendable | wallet-derived | required | computed |
| Imported private root | spendable | wallet-derived | required | computed |
| Imported XPub, unnumbered | watch-only | imported | absent | optional |
| Imported XPub, numbered | watch-only | imported | required | optional |

The persisted `is_derived` fact and the public `IsImported` result distinguish
a wallet-derived account key from an imported account key. An optional account
number distinguishes numberless imports from imports with a known number.
Accounts derived from an imported private wallet root remain wallet-derived.

For a numbered import, the caller declares the purpose and coin type. The
caller may also supply the master fingerprint. The account number comes from
the hardened child index of the XPub.

The wallet validates the network, depth and hardened account child of the key.
The wallet cannot authenticate the hardened purpose or coin ancestors or the
supplied fingerprint. `ImportAccountParams.MasterKeyFingerprint` uses the
wallet-owned `*MasterFingerprint`. SQL preserves nil as absent. SQL preserves a
non-nil zero as a valid supplied fingerprint. The BIP32 fingerprint is a
four-byte hash prefix and can be all zero. Thus zero cannot also represent
omission.

Legacy kvdb rows have only a scalar fingerprint. When metadata is omitted,
these rows keep their existing zero default. This behavior does not add
optional-metadata parity to kvdb. Wallet-derived accounts use the
wallet-computed fingerprint.

#### Account Creation Requests

`NewAccountParams` keeps these inputs to derive an account from the wallet
seed: name, scope, optional account number, address schema and `NoChainSync`.
Existing account XPubs are imported through `ImportAccount`.

`ImportAccount` accepts `ImportAccountParams` and the existing `dryRun`
argument. The renamed existing account record also supplies
`CreateWalletParams.InitialAccounts`. Thus initial imports and live imports
share the same key, name, fingerprint, scope and schema validation.

A nil `Scope` keeps XPub-version/address-type inference and a numberless
import. A declared `Scope` keeps the number that the hardened account child of
the XPub encodes. `AddrSchema` requires a declared scope. When `AddrSchema` is
omitted, canonical scopes use their existing default schema. Custom scopes
require an `AddrSchema`. The declared purpose and coin type select the scope
independently of the extended-key version. The extended-key version is still
checked for the configured network.

Both SQL backends reuse the imported-account transaction. This transaction
inserts the optional number and advances the existing `next_account_number`
cursor. Numbered imports remain `is_derived=false`. They must return the
requested effective schema before commit. Failures and dry runs roll back
account, secret, scope and cursor writes.

kvdb reuses its watch-only account writer at the known number. kvdb advances
its existing account cursor and does not consume lower holes. The existing kvdb
account metadata record keeps the optional number with the timestamp. Old
imports and inferred imports keep an unknown number. On either backend, account
and address reads, numeric selection and reopening preserve declared imports.

On SQL backends, the shared import input accepts `NoChainSync`. The default is
false. The flag uses the existing account policy to exclude the account from
automatic chain synchronization. Legacy kvdb ignores this flag and reports
false. `AccountInfo` exposes the immutable fact, but does not make the fact a
custody or signing signal.

Before wallet startup, lnd's online remote-signer wallet imports external
account XPubs. These XPubs include purpose-1017 key-family accounts and mixed
BIP49 schemas. These inputs fit the existing import and initial-account paths.

#### Chain Synchronization

`NoChainSync` is an immutable boolean. It is independent of wallet-level signing
custody:

| Wallet custody | `NoChainSync=false` | `NoChainSync=true` |
| --- | --- | --- |
| Spendable | automatic chain sync | excluded from automatic chain sync |
| Uniformly watch-only | automatic chain sync | excluded from automatic chain sync |

When `NoChainSync` is false, the account participates in automatic chain
discovery and live script registration. When `NoChainSync` is true, the derived
scripts of the account are excluded from both. Neither value changes address
ownership, public child derivation, or signing capability. Also, neither value
causes the wallet to discard an owned transaction that the wallet learned
through another ingestion path. Signing still follows the existing custody
model of the wallet.

#### Scope And Branch Schema

If the address schema is omitted, the request reuses the persisted schema of an
existing scope or the canonical schema for a standard scope. A new custom scope
requires an explicit schema. A schema supplied for an existing scope is an
equality assertion. Any external/internal branch mismatch is a conflict. In
that case, the request fails before mutation.

Each branch must be derivable from a single account key. The supported forms
are:

- P2PKH (`PubKeyHash`)
- P2SH-P2WPKH (`NestedWitnessPubKey`)
- P2WPKH (`WitnessPubKey`)
- key-path P2TR (`TaprootPubKey`)

Other forms are not account schemas.

For collision comparison in one wallet, the normalized payload of an account
XPub is its public key and chain code. These values do not distinguish that
payload:

- version bytes
- depth
- parent fingerprint
- child number
- name
- optional account number
- provenance
- declared master fingerprint

Accounts with equal normalized payloads conflict when one of these pairs can
derive the same scripts:

- their corresponding external branch schemas
- their corresponding internal branch schemas

External and internal branches are not cross-compared, because their `/0/` and
`/1/` derivation paths are disjoint. Admission is allowed only when both
corresponding branch-schema pairs are disjoint. Equal normalized payloads in
one scope always conflict, because accounts in that scope share its effective
schema.

Existing schema fields remain, including `coin_pub_key`, `key_scope_secrets`,
and all other columns. Account-shape constraints and affected validation and
read paths must admit a caller-supplied numbered account with
`is_derived=false` and a non-null `account_number`. They must also preserve the
root-derived numbered shape and the caller-supplied unnumbered shape.

#### Store Adapter Identity

The shared Store projection needs a stable account selector for each backend.
But that selector is not a public account identity. The internal
`db.AccountInfo.AccountID` field carries the persisted identity of the backend
adapter. SQL maps the field from `accounts.id`. kvdb maps the field from the
internal account number of waddrmgr.

Shared code identifies this adapter value by the `(KeyScope, AccountID)` pair.
kvdb account numbers restart in every key scope. Thus an `AccountID` can recur
in one wallet. SQL row IDs happen to have wider uniqueness. But shared code
must not depend on that backend-specific property.

kvdb populates the adapter identity for these accounts:

- wallet-derived accounts
- imported-XPub accounts
- its imported-address pseudo-account

Under the legacy ordinary-import contract, an imported account has no public
`AccountNumber`. But waddrmgr still persists an unmasked internal account
number for scoped lookup. Recovery also uses the adapter identity to key
per-account state and to stamp scan horizons. If kvdb returned no adapter
identity, imported-account recovery and numeric kvdb lookup would be ambiguous
or unusable.

`AccountNumber` remains an optional known hardened account component.
`AccountName` remains mutable display and lookup metadata. The adapter ID of a
wallet-derived kvdb account may numerically equal its account number. That
coincidence does not give the two fields the same meaning. The coincidence also
does not prove provenance.

The adapter identity is stable only for an account within its backing Store and
backend-defined domain. SQL row IDs and kvdb account numbers:

- are not comparable.
- may repeat across key scopes or wallets.
- may change during a backend conversion.

These values must remain inside the Store, recovery, and adapter lookup
boundaries. A wallet-owned public account contract must not expose any of these
values as a portable account ID:

- the adapter value of either backend
- an SQL row ID
- the current `RecoveryState.AccountID` accessor

#### Account Alternatives

The first rejected alternative was to continue to map unnumbered
caller-supplied XPub accounts to account number `0`. That alternative preserves
compatibility with BIP44-shaped callers. But it makes unnumbered imports collide
with the default wallet-derived account. It also forces runtime code to
distinguish fake `0` from real `0`.

The second rejected alternative was to split BIP44 account numbers into a
`derived_accounts` table. That alternative matched the subtype model. But it
mostly moved one nullable field out of `accounts`. It also added another join
and a parent/child shape invariant. A row-local check on `accounts` is simpler.
The check also still prevents unnumbered caller-supplied XPub accounts from
being mistaken for account `0`.

The accepted tradeoff is a nullable `account_number` that is interpreted
together with immutable account provenance. This tradeoff:

- keeps the invariant local to the account row.
- admits a truthful numbered caller-supplied path.
- still removes fake identity.

A new path table is unnecessary, because `accounts` already holds the scope,
optional number, XPub and fingerprint. A second public import method, a
duplicate input record or a compatibility wrapper would repeat existing import
behavior. Rename the shared record to `ImportAccountParams`. Do not add another
type. Keep the import of existing keys separate from wallet-seed derivation.

#### Account Consequences

Pros:

- Unnumbered caller-supplied XPub accounts can no longer be mistaken for
  account `0`.
- Numbered lookup can represent both root-derived and numbered
  caller-supplied accounts without accepting a backend ID.
- SQL recovery can key unnumbered-XPub scan horizons by the immutable internal
  `account_id`. Public code uses semantic selectors.
- Account lists remain low-cardinality reads over one identity table.

Cons:

- Go callers must treat account numbers as optional.
- Code that handles unnumbered caller-supplied accounts must not collapse SQL
  NULL to Go zero.
- Read paths must consistently reject impossible account shapes.

### Addresses

`addresses` is the stable wallet-local script identity table. It holds these
fields:

- wallet
- script pubkey
- script type
- creation time
- imported public-key material
- a structural `is_derived` bit

The table does not store scope, account, branch, or index.

`derived_addresses` stores HD child ownership and path data: wallet ID, account
ID, branch, and index. A derived address inherits its scope through the owning
account:

```text
derived_addresses.account_id -> accounts.scope_id
```

Raw imported addresses are `addresses` rows with no `derived_addresses` child.
These rows have no account, no scope, no branch, and no index.

The reserved name `imported` remains a user-facing compatibility alias for raw
imported addresses. The name is not materialized as an SQL account row. APIs
that list raw imported addresses use an accountless query. In that query, both
`Scope` and `AccountName` are unset. UTXO and balance filters do not have an
SQL selector for raw imports only. Nil filters mean the whole wallet. Account
filters match real accounts only.

Address identity fields are immutable after creation. These fields include
`id`, `wallet_id`, and `is_derived`. `derived_addresses` rows are insert-only,
because their account ownership and address path data are structural identity
facts.

#### Address Alternatives

The first rejected alternative was to store raw imported addresses under an SQL
account named `imported`. ADR 0012 chose that bucket shape for the earlier
watch-only decision. This identity decision rejects that shape for SQL, because
the shape gives raw imports fake account and scope identity. The reserved name
remains only as a wallet-facing alias.

The second rejected alternative was to keep nullable `account_id`,
`address_branch`, and `address_index` columns on `addresses`. That alternative
would make the derived/raw invariant row-local. But it would also make the base
address table carry HD path columns that have no meaning for raw imports.

The accepted tradeoff is a `derived_addresses` subtype table. The subtype table
adds a join and requires consistent shape checks. But the table keeps raw
imports as wallet-local script identity only. The table also lets
derived-address indexes start from account/path facts.

#### Address Consequences

Pros:

- Raw imported addresses no longer require a fake account row.
- Raw imports no longer carry fake scope or derivation-path identity.
- Unnumbered-XPub, numbered-XPub, and wallet-root-derived child addresses share
  the same derived-address path model.
- Derived address queries can start from account/path facts. Raw import
  queries can start from wallet-local script identity.
- Account-scoped address creation and address-index checks can use
  `derived_addresses(account_id, branch, index)` without a scan of raw imports.
- Script and UTXO reads can join to derived-path metadata only when callers need
  account ownership. Raw imports stay anchored by wallet/script identity.

Cons:

- Address reads need additional joins and generated query churn.
- Write workflows and database constraints own parent/child shape validation.
  Read paths should not duplicate those checks on UTXO and balance queries.
- Raw-import compatibility paths must not rely on a scoped SQL account alias.

## 3. Implementation Notes

- Modify the existing unmerged account and address migrations in place. Do not
  add new migration numbers for this feature-branch schema rewrite.
- The normalized schema applies to the PostgreSQL and SQLite backends. kvdb
  keeps its legacy waddrmgr storage. This storage includes the fixed imported
  account name and the scoped imported buckets. kvdb only maps legacy rows into
  the shared Go types.
- `db.AccountInfo` exposes an internal adapter `AccountID` and makes
  `AccountNumber` optional. SQL maps `AccountID` from `accounts.id`. kvdb maps
  `AccountID` from the per-scope internal account number of waddrmgr. SQL
  account numbers are present for root-derived and numbered caller-supplied
  accounts. SQL account numbers are absent for unnumbered caller-supplied
  accounts. Shared code pairs the adapter identity with `KeyScope`. Shared code
  must not expose the adapter identity as a portable public account ID.
- `db.AddressInfo` makes `AccountID` and `AccountNumber` optional. SQL raw
  imports have neither field. They use an empty account name and a zero key
  scope. An accountless query lists them. Unnumbered-XPub child addresses
  inherit an account ID and scope from their account, but have no account
  number. Numbered-XPub children keep their real number.
- `AddressDerivationParams` carries an optional account number. Unnumbered-XPub
  child addresses must not synthesize `0` and accidentally claim a full public
  origin or derive wallet-seed keys. A numbered caller-supplied child may
  report its caller-declared origin when its fingerprint is also known. In that
  case, the child does not claim that the wallet authenticated its hardened
  ancestors. Missing fingerprint metadata omits the complete public origin, but
  the child keeps its branch/index. An explicitly supplied zero remains known.
- `ListAddressesQuery` uses pointer selectors:
  - Both `Scope` and `AccountName` set means account-scoped derived children.
  - Both nil means raw imported addresses.
  - One set without the other is invalid.
- `ListUTXOs` account filters match real accounts only. A nil account filter is
  wallet-wide and includes raw imports. Thus higher layers that expose the
  reserved imported alias must filter accountless raw-import UTXOs locally.
- Low-cardinality account lists may start from `accounts`. Derived address reads
  can start from account/path data. Raw imported address reads can start from
  wallet-local script identity.

## 4. References

- [ADR 0006](0006-wtxmgr-sql-schema.md): SQL transaction schema.
- [ADR 0011](0011-no-addresses-used-column.md): SQL derives address used-ness
  from wallet transaction state.
- [ADR 0012](0012-wallet-level-watch-only-uniformity.md): wallet root mode and
  effective account custody. This ADR supersedes its SQL imported-address
  bucket shape. Raw imports now use the reserved name only as an alias, not as
  a stored account row.
- [lnd watch-only account imports](https://github.com/lightningnetwork/lnd/blob/d932f48678228e337a7cc75ee4e864245e6e2b99/config_builder.go#L1608).
