# Architecture Decision Records (ADRs)

This directory contains [Architecture Decision Records (ADRs)](https://github.com/joelparkerhenderson/architecture-decision-record) for the `btcwallet` project. ADRs are short, focused documents that capture significant architectural decisions, their context, the options considered, and their consequences.

ADRs serve as a historical log of important design choices, providing context for future development and helping new contributors understand the rationale behind the system's architecture.

## Existing ADRs

- [ADR 0001: Multi-Wallet Architecture](./0001-multi-wallet-architecture.md) - Decides on the architecture for managing multiple distinct wallets and networks within a single daemon instance.
- [ADR 0002: Controller-Syncer-State Architecture](./0002-controller-syncer-architecture.md) - Decouples lifecycle management, synchronization logic, and state tracking from the monolithic `Wallet` struct.
- [ADR 0003: Optimistic CFilter Batch Scanning](./0003-optimistic-cfilter-batching.md) - Optimizes BIP 157/158 Compact Filter synchronization using optimistic batch scanning.
- [ADR 0004: Targeted Rescan vs. Global Rewind](./0004-targeted-rescan-vs-rewind.md) - Introduces "Targeted Rescans" to replace global "Rewinds" for more efficient transaction discovery.
- [ADR 0005: Explicit Rescan on Import](./0005-no-auto-rescan-on-import.md) - Disables automatic blockchain scanning during import operations, requiring explicit user initiation.
- [ADR 0006: Wallet Transaction Manager SQL Schema](./0006-wtxmgr-sql-schema.md) - Defines the relational SQL schema for the Wallet Transaction Manager (`wtxmgr`) migration.
