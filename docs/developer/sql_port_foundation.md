# SQL Port Foundation

## Scope

In this stage, we add the SQL build, connection, and migration foundation
without changing how `Wallet`, `waddrmgr`, or `wtxmgr` behave. The existing KV
path remains the reference implementation. SQLite and PostgreSQL are new
internal persistence targets behind the same wallet API.

The first schema slice contains block metadata only. Wallet, account, address,
transaction, UTXO, and lease tables land in later commits once their migration
contract has been checked against the current KV representation.

## `lnd/sqldb`

This stage uses the released `github.com/lightningnetwork/lnd/sqldb` module at
`v1.0.13` as the common SQL utility layer. In particular, the SQLite connection
defaults come directly from that module. Its transaction executor, retry
policy, backend-neutral error mapping, nullable-value helpers, and pagination
helpers are available to the later store adapter without copying those
utilities into btcwallet.

The schema and migration runners remain local to btcwallet. The concrete lnd
stores embed lnd's own schema and global migration ordering, while btcwallet
needs backend-specific triggers, functions, sequences, and table constraints.
The local wrappers also expose the down/target operations used by the rollback
gate. Sharing the utility layer without sharing the application schema keeps
the dependency boundary narrow.

We also evaluated the nested `github.com/lightningnetwork/lnd/sqldb/v2`
development module. It has useful connection work, but it has no released v2
tag and currently relies on a module-local `golang-migrate` replacement that
would not propagate to btcwallet. We therefore use the stable v1 module now
and leave a v2 upgrade as a normal dependency update once that line is
released.

## Compatibility Constraints

The wallet/address schema cannot be copied from `sql-wallet` unchanged. That
branch intentionally combines the storage port with a new encryption and
address-history model.

The port-first schema keeps the current dual-passphrase hierarchy. It must
represent the master public/private KDF parameters, all three encrypted crypto
keys, encrypted master HD public/private keys, and encrypted public/private
material at the scope, account, and address layers. Watch-only wallets retain
the current nullability rules, including the script fallback through the public
crypto key.

The port-first schema also persists the legacy sticky address-used bit. KV can
mark an address used without retaining enough transaction or UTXO history to
derive that fact later. Deriving used-ness from `EXISTS(utxos)` would therefore
change `LastUnusedAddress` and gap-limit behavior after migration.

These are storage compatibility requirements, not endorsements of the legacy
model forever. The single-passphrase/key-vault and history-derived address
designs can return as separate refactors after the SQL port has migration and
`lnd` end-to-end coverage.

## Verification

Every schema slice must regenerate cleanly with `make sqlc-check`. SQLite and
PostgreSQL migrations must both pass an empty-to-head, head-to-empty, and
empty-to-head round trip. No PR in this stage may change an exported wallet API
or require an `lnd` source adaptation.
