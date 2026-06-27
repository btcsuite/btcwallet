# ADR 0012: Wallet-Level Watch-Only as a Uniform Invariant

## 1. Context

The legacy `waddrmgr` address-manager supports a richer watch-only model than
modern descriptor wallets:

- The wallet carries a top-level `is_watch_only` flag.
- Individual accounts can additionally be watch-only (e.g. an imported
  xpub-only account inside an otherwise-spendable wallet).
- Reports such as `AccountProperties().IsWatchOnly` compute an "effective"
  per-account watch-only state by combining the wallet flag with the
  presence of account-level private-key material.

This per-account nuance has wide-ranging consequences for the SQL store and
the wallet API:

- Read paths compute watch-only state via joins against the encrypted
  secrets table (`account_secrets`), creating cross-cutting dependencies
  between read flows and the signer surface. UTXO listing, transaction
  listing, and address listing all become coupled to a table whose only
  legitimate consumer is the signer.
- Balance reporting has to distinguish a wallet's "spendable" total from
  its "watch-only" total, with separate accumulation paths and separate
  API shapes for the two categories.
- Importing or removing a watch-only account changes a wallet's effective
  signing capability at runtime, complicating audit, caching, and the
  wallet's lifecycle reasoning.

Bitcoin Core introduced descriptor wallets in v0.21.0 and made them the
default for new wallets in v23.0. In that descriptor-wallet model:

- Is created with `disable_private_keys` set to true or false; the flag
  is immutable after creation.
- Rejects descriptor imports whose mode conflicts with the wallet:
  > Cannot import descriptor without private keys to a wallet with
  > private keys enabled.
- Surfaces the wallet's mode through `getwalletinfo`'s
  `private_keys_enabled` field and emits a single `mine` bucket from
  `getbalances` — the `watchonly` sub-bucket only persists for
  deprecated pre-descriptor wallets.

## 2. Decision

A btcwallet wallet is uniformly watch-only or uniformly spendable. The
state is recorded in `wallets.is_watch_only`, set at wallet creation, and
immutable thereafter. Imports whose mode conflicts with the wallet are
rejected at the store boundary by application-level validation that runs
uniformly on both SQL backends.

Implications:

- A non-watch-only wallet rejects imports that would introduce
  watch-only-only material (an imported xpub account without matching
  encrypted account private-key material, or an imported address
  without encrypted private-key material).
- A watch-only wallet symmetrically rejects imports that would introduce
  spendable material.
- Balance reporting on the wallet-internal surface returns a single
  category. There is no `watchonly` sub-bucket. The wallet's watch-only
  state is surfaced via `Wallet.IsWatchOnly()`.
- Users that want to track watch-only material alongside a spendable
  wallet create a second wallet for that purpose, matching Core.
- Read paths (UTXO listing, transaction listing, address listing) do not
  consult `account_secrets`. Watch-only state is a wallet-level
  constant cached on the `Wallet` struct at startup.

The legacy JSON-RPC contract (`getbalance`, `listaccounts`,
`includeWatchOnly`) keeps emitting and accepting its historical fields so
external consumers do not break. Wallet-internal callers migrate to the
single-bucket shape.

### Imported addresses use a reserved compatibility alias

ADR 0013 supersedes the earlier stored SQL imported-address bucket shape. The
reserved name `imported` remains as a compatibility alias for raw imported
address APIs, but normalized SQL stores raw imported addresses directly under the
wallet and scope without materializing an account row.

An imported address — with or without private-key material — is never
treated as a member of a wallet-derived (HD) account. The alias is reserved —
`CreateDerivedAccount` and `CreateImportedAccount` both reject
`DefaultImportedAccountName` with `ErrReservedAccountName`, so neither a derived
account nor a true imported xpub account can occupy the compatibility name.

The spendable-wallet invariant applies **per imported address**:

- On a spendable wallet, an imported address must carry its own
  `encrypted_priv_key`. A public-only or script-only address import is
  rejected with `ErrSpendableWalletNeedsAddressPrivKey`.
- On a watch-only wallet, the same imported address is public-only and is
  accepted; a private-key-bearing import is rejected with
  `ErrWatchOnlyViolation`.

Derived addresses are unaffected: they inherit their key material from the
account xpub/xpriv and are reached through `AccountKeyFromParams` (the
caller-supplied account name), never through the raw-import compatibility alias.

### P2A / anchor outputs are transaction state, not imports

Pay-to-anchor (P2A) outputs are keyless by construction (`OP_1
<0x4e73>`): there is no private key to import and none to require. Although
Bitcoin Core can encode P2A as an address/destination, a P2A is not useful as
long-lived wallet address material. Its relevance comes from the transaction
flow that created it, typically as a temporary anchor used by a child
transaction to fee-bump its parent.

This ADR therefore treats P2A as transaction/output state, not as a standard
managed or imported address. A spendable wallet that needs to observe an anchor
tracks the concrete output through the relevant-output / watched-outpoint path,
not by importing an address row. No imported-address or address-secret row is
created for the anchor, so no symmetric-invariant exception is needed: the
invariant never triggers on a path the anchor does not travel. The child
transaction that spends and fee-bumps the parent signs with the wallet's own
key material on its other inputs/outputs; the keyless anchor input contributes
no signature, so the spend flow stays safe under the uniform wallet-level
model.

## 3. Consequences

- `db.UtxoInfo` does **not** carry an `IsWatchOnly` field. Wallet-level
  state, cached on the `Wallet` struct, applies uniformly to every UTXO
  row.
- `db.AccountInfo.IsWatchOnly` and `db.AddressInfo.IsWatchOnly` are
  retained as wallet-level convenience copies. They are documented as
  identical across every account or address belonging to the same
  wallet. A future cleanup task may remove them; callers that want the
  canonical reading use `Wallet.IsWatchOnly()`.
- `NewImportedAddressParams.IsWatchOnly()` is removed. The params struct
  does not carry wallet-level state, and the per-row "watch-only because
  no private key" condition cannot occur in a spendable wallet under
  this invariant.
- Per-account `is_watch_only` computations in account-read queries
  (`GetAccountByWalletScopeAndName` and its equivalents) drop their
  `LEFT JOIN account_secrets` clause; the value is projected directly
  from `wallets.is_watch_only`.
- A new symmetric invariant — enforced by application-level validation at
  the store boundary, uniformly on both SQL backends — asserts that a
  spendable wallet's true imported (xpub) accounts and its imported
  addresses carry the matching secret material. The existing
  one-directional checks (watch-only wallets cannot store secrets) are
  preserved. The invariant is deliberately **not** backed by a database
  trigger: a trigger cannot be expressed identically on SQLite (whose
  triggers are not deferrable), would duplicate the application-level check,
  and is bypassable by out-of-band writes — so one application-level check
  for both backends is the single source of truth.
- The symmetric secret requirement applies to **imported** material and
  exempts the keyless imported-address bucket by design. The account-level
  check (`requireAccountPrivKeyOnSpendable`) runs in `CreateImportedAccount`,
  the path for true imported (xpub) accounts, and requires account-level
  secret material on a spendable wallet. The keyless imported bucket does not
  travel that path — it is materialized by a dedicated keyless insert and
  holds no account-level secret — so it is exempt; the per-address check is
  what enforces spendability for the addresses it holds.
- Derived accounts are not watch-only just because they are read without
  looking at `account_secrets`: the wallet-level flag is the public
  watch-only signal. Spendable derived accounts may persist encrypted
  account private-key material in `account_secrets`; the unlocked signing
  material used at runtime is derived from wallet key material. Derived
  addresses still do not store per-address private keys in `address_secrets`.
  Requiring a per-address secret for a derived row would contradict the HD
  design — a derived address in a spendable wallet is spendable because the
  wallet holds the relevant wallet/account key material, so absence of an
  address secret is not a watch-only signal. Only an *imported* row lacking
  the secret material required by this invariant indicates watch-only-only
  material, which is what the invariant forbids on a spendable wallet.
- This ADR does not remove `account_secrets` or `key_scope_secrets`; it only
  removes account/address secret presence as a public watch-only inference
  source.
- The invariant is enforced at imported-account / imported-address
  **create time**, application-side and uniformly on both SQL backends (the
  `ValidateWatchOnly` and spendable-secret checks at the store boundary).
  Because the wallet-level `is_watch_only` flag is immutable after creation
  (no `UpdateWallet` path mutates it), the new SQL store cannot reach the
  legacy mixed-mode shape, so no load-boundary re-check is required.
  The legacy kvdb backend is grandfathered: its data model still
  permits an imported watch-only account inside a spendable wallet (the
  historical `importpubkey` / `importaddress` flow). This ADR's uniform
  invariant is a property of the new SQL store, not a retrofit onto
  kvdb.

## 4. References

- [ADR 0006](0006-wtxmgr-sql-schema.md): wtxmgr SQL schema (related).
- [ADR 0011](0011-no-addresses-used-column.md): addresses table omits the
  `used` column (related — also a "compute, don't persist" choice; this ADR
  makes the opposite call by persisting wallet-level watch-only).
- [Bitcoin Core v23.0 release notes][btc-core-v23-release]: documents
  descriptor wallets becoming the default wallet type for new wallets.
- [Bitcoin Core `createwallet` documentation][btc-core-createwallet]:
  documents the `disable_private_keys` flag whose immutable wallet-level
  semantics this ADR matches.
- [Bitcoin Core descriptor import implementation][btc-core-importdescriptors]:
  `wallet/rpc/backup.cpp` `ProcessDescriptorImport()` is the source for
  the rejection btcwallet mirrors — a descriptor without private keys
  cannot be imported into a wallet with private keys enabled (and the
  symmetric direction). The matching error string lives in the same
  function.

[btc-core-v23-release]: https://bitcoincore.org/en/releases/23.0/
[btc-core-createwallet]: https://bitcoincore.org/en/doc/31.0.0/rpc/wallet/createwallet/
[btc-core-importdescriptors]: https://github.com/bitcoin/bitcoin/blob/v31.0/src/wallet/rpc/backup.cpp
