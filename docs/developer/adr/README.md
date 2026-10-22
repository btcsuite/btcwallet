# Architecture Decision Records (ADRs)

This directory contains
[Architecture Decision Records (ADRs)](https://github.com/joelparkerhenderson/architecture-decision-record)
for the `btcwallet` project. ADRs are short, focused documents. Each ADR
records a significant architectural decision, its context, the options
considered, and its consequences.

ADRs are a historical log of important design choices. The ADRs give context
for future development. The ADRs also help new contributors understand the
rationale for the system architecture.

## Authoring ADRs

Copy [the ADR template](./template.md) to a file named
`NNNN-short-title.md`. Use the next available four-digit number and a concise
kebab-case title. Then do these steps:

1. Replace every instructional comment.
2. Complete every section.
3. Wrap Markdown near 80 columns.
4. Add the ADR to the index below.

Each ADR has exactly one decision status:

- `Proposed`: under discussion and not authoritative.
- `Accepted`: approved and authoritative for the current architecture.
- `Rejected`: considered but not approved.
- `Deprecated`: no longer authoritative and not replaced by one specific ADR.
- `Superseded`: fully replaced by the ADR named in `Superseded by`.

Implementation progress is not a decision status. Record implementation
progress in the implementation overview or references instead. An ADR written
before this template that omits a status is treated as `Accepted`, unless a
relationship link says otherwise. The legacy `Accepted and Implemented`
wording is also equivalent to `Accepted`.

Use `Amends` for a compatible, partial change. The earlier ADR remains
`Accepted` and links back with `Amended by`. Use `Supersedes` when a new ADR
fully replaces an earlier decision. The earlier ADR then becomes `Superseded`
and links back with `Superseded by`. Add both sides of either relationship in
the same change. When you relate a legacy ADR, add its normalized status and
relationship metadata. Do not rewrite its historical decision body.

## Existing ADRs

- [ADR 0001: Multi-Wallet Architecture](./0001-multi-wallet-architecture.md) -
  Decides the architecture to manage multiple distinct wallets and networks
  in a single daemon instance.
- [ADR 0002: Controller-Syncer-State
  Architecture](./0002-controller-syncer-architecture.md) -
  Records the historical Controller/Syncer/State decision. ADR 0015
  supersedes this ADR.
- [ADR 0003: Optimistic CFilter Batch
  Scanning](./0003-optimistic-cfilter-batching.md) -
  Optimizes BIP 157/158 Compact Filter synchronization with optimistic batch
  scanning.
- [ADR 0004: Targeted Rescan vs. Global
  Rewind](./0004-targeted-rescan-vs-rewind.md) -
  Introduces targeted rescans in place of global rewinds. ADR 0005 amends this
  ADR for explicit import recovery. ADR 0015 amends this ADR for SQL
  targeted-rescan ownership.
- [ADR 0005: Explicit Rescan on Import](./0005-no-auto-rescan-on-import.md) -
  Requires callers to initiate historical recovery after imports. Amends the
  import trigger and target scope of ADR 0004.
- [ADR 0006: Wallet Transaction Manager SQL
  Schema](./0006-wtxmgr-sql-schema.md) -
  Defines the relational `wtxmgr` schema. ADR 0015 amends this ADR for SQL
  block identity and canonical-frontier semantics.
- [ADR 0007: XChaCha20-Poly1305
  Encryption](./0007-xchacha20-poly1305-encryption.md) -
  Replaces XSalsa20-Poly1305 with XChaCha20-Poly1305 to encrypt private key
  material.
- [ADR 0008: Integration Test
  Framework](./0008-integration-test-framework.md) -
  Defines a modular integration test framework for permutations of chain and
  database backends.
- [ADR 0009: Single-Passphrase Encryption
  Model](./0009-single-passphrase-encryption.md) -
  Adopts a single-passphrase model. The model encrypts only private data and
  keeps public wallet metadata in plaintext.
- [ADR 0010: Keyvault Encryption
  Layer](./0010-keyvault-encryption-layer.md) -
  Defines an in-memory keyvault boundary between domain logic and SQL
  persistence. The boundary handles lock state, key lifecycle, and encryption
  orchestration.
- [ADR 0011: No `used` Column on the Addresses
  Table](./0011-no-addresses-used-column.md) -
  Records that the SQL backend derives address used-ness from the utxos table
  and does not persist a separate column. The utxos table is monotonic
  because of the soft-delete schema of ADR 0006. The kvdb backend continues
  to use the legacy sticky-bit of waddrmgr, because wtxmgr deletes credit
  records on reorg.
- [ADR 0012: Wallet Root Mode and Account
  Custody](./0012-wallet-level-watch-only-uniformity.md) -
  Preserves immutable root mode and permits imported XPub accounts alongside
  local signing accounts. The decision uses provenance and output
  spendability.
- [ADR 0013: Normalized Account and Address
  Identity](./0013-normalized-account-address-identity.md) -
  Normalizes SQL account/address identity around nullable account numbers,
  derived-address path rows, and accountless raw imports.
- [ADR 0014: Durable SQL Database Identity](./0014-sql-database-identity.md) -
  Defines the durable role-wallet identity and the identity-first
  initialization order for SQLite and PostgreSQL.
- [ADR 0015: Manager Lifecycle and SQL Shared-Chain
  Ownership](./0015-sql-shared-chain-ownership.md) -
  Supersedes ADR 0002. Applies aggregate lifecycle and admission to every
  maintained Manager, and assigns SQL shared-chain ownership.
- [ADR 0016: Wallet Transaction
  Subscriptions](./0016-wallet-transaction-subscriptions.md) -
  Defines best-effort Wallet notifications with bounded subscriber queues.
