# Architecture Decision Records (ADRs)

This directory contains [Architecture Decision Records (ADRs)](https://github.com/joelparkerhenderson/architecture-decision-record) for the `btcwallet` project. ADRs are short, focused documents that capture significant architectural decisions, their context, the options considered, and their consequences.

ADRs serve as a historical log of important design choices, providing context for future development and helping new contributors understand the rationale behind the system's architecture.

## Authoring ADRs

Copy [the ADR template](./template.md) to a file named
`NNNN-short-title.md`, using the next available four-digit number and a concise
kebab-case title. Replace every instructional comment, complete every section,
wrap Markdown near 80 columns, and add the ADR to the index below.

Each ADR has exactly one decision status:

- `Proposed`: under discussion and not authoritative.
- `Accepted`: approved and authoritative for the current architecture.
- `Rejected`: considered but not approved.
- `Deprecated`: no longer authoritative and not replaced by one specific ADR.
- `Superseded`: fully replaced by the ADR named in `Superseded by`.

Implementation progress is not a decision status. Record it in the
implementation overview or references instead. ADRs written before this
template that omit a status are treated as `Accepted` unless a relationship
link says otherwise. The legacy `Accepted and Implemented` wording is also
equivalent to `Accepted`.

Use `Amends` for a compatible, partial change. The earlier ADR remains
`Accepted` and links back with `Amended by`. Use `Supersedes` when a new ADR
fully replaces an earlier decision. The earlier ADR then becomes `Superseded`
and links back with `Superseded by`. Add both sides of either relationship in
the same change. When relating a legacy ADR, add its normalized status and
relationship metadata, but do not rewrite its historical decision body.

## Existing ADRs

- [ADR 0001: Multi-Wallet Architecture](./0001-multi-wallet-architecture.md) - Decides on the architecture for managing multiple distinct wallets and networks within a single daemon instance.
- [ADR 0002: Controller-Syncer-State Architecture](./0002-controller-syncer-architecture.md) - Decouples lifecycle management, synchronization logic, and state tracking from the monolithic `Wallet` struct.
- [ADR 0003: Optimistic CFilter Batch Scanning](./0003-optimistic-cfilter-batching.md) - Optimizes BIP 157/158 Compact Filter synchronization using optimistic batch scanning.
- [ADR 0004: Targeted Rescan vs. Global Rewind](./0004-targeted-rescan-vs-rewind.md) - Introduces "Targeted Rescans" to replace global "Rewinds" for more efficient transaction discovery.
- [ADR 0005: Explicit Rescan on Import](./0005-no-auto-rescan-on-import.md) - Disables automatic blockchain scanning during import operations, requiring explicit user initiation.
- [ADR 0006: Wallet Transaction Manager SQL Schema](./0006-wtxmgr-sql-schema.md) - Defines the relational SQL schema for the Wallet Transaction Manager (`wtxmgr`) migration.
- [ADR 0007: XChaCha20-Poly1305 Encryption](./0007-xchacha20-poly1305-encryption.md) - Replaces XSalsa20-Poly1305 with XChaCha20-Poly1305 for encrypting private key material.
- [ADR 0008: Integration Test Framework](./0008-integration-test-framework.md) - Defines a modular integration test framework for chain and database backend permutations.
- [ADR 0009: Single-Passphrase Encryption Model](./0009-single-passphrase-encryption.md) - Adopts a single-passphrase model that encrypts private data only while keeping public wallet metadata in plaintext.
- [ADR 0010: Keyvault Encryption Layer](./0010-keyvault-encryption-layer.md) - Defines an in-memory keyvault boundary for lock state, key lifecycle, and encryption orchestration between domain logic and SQL persistence.
- [ADR 0011: No `used` Column on the Addresses Table](./0011-no-addresses-used-column.md) - Records the decision that the SQL backend derives address used-ness from the utxos table (monotonic by ADR 0006's soft-delete schema) rather than persisting a separate column. The kvdb backend continues to use waddrmgr's legacy sticky-bit because wtxmgr deletes credit records on reorg.
- [ADR 0012: Wallet-Level Watch-Only as a Uniform Invariant](./0012-wallet-level-watch-only-uniformity.md) - Records that SQL wallets are uniformly watch-only or uniformly spendable, with wallet-level mode enforced at the store boundary.
- [ADR 0013: Normalized Account and Address Identity](./0013-normalized-account-address-identity.md) - Normalizes SQL account/address identity around nullable account numbers, derived-address path rows, and accountless raw imports.
