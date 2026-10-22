# ADR 0004: Targeted Rescan vs. Global Rewind

## Status

- **Status:** Accepted
- **Date:** 2025-12-25

## Relationships

- **Amends:** None.
- **Supersedes:** None.
- **Amended by:** [ADR 0005](0005-no-auto-rescan-on-import.md) for explicit
  import recovery and wallet-wide targets;
  [ADR 0015](0015-sql-shared-chain-ownership.md) for SQL targeted-rescan
  ownership.
- **Superseded by:** None.

> **Amended by ADR 0005:** ADR 0005 changes the automatic import trigger in
> Section 2.2. Imports may register a live watch after persistence, but they do
> not start historical recovery. Callers invoke `Rescan(...)` explicitly.
> ADR 0005 also amends the account-exclusive target description in
> Section 2.2:
> - Requested accounts limit derivation horizons.
> - Recovery-relevant addresses and UTXOs are loaded wallet-wide.
>
> A targeted rescan still does not rewind the global `SyncedTo` watermark.

## 1. Context

In `btcwallet`, the discovery of missing transactions historically required a
"Rescan." The legacy implementation treated all rescans as a "Rewind":
1.  Set the wallet's global `SyncedTo` height back to the start block.
2.  Force the wallet into a `Syncing` state.
3.  Re-process all blocks from that height forward.

This "Global Rewind" approach causes problems for modern use cases, like the
import of a single private key or account.
*   **Disruption:** The rewind forces the entire wallet to be "unsynced" for
    minutes or hours. During that time, the rewind blocks critical operations
    like transaction creation, although the existing keys are fully
    up-to-date.
*   **Inefficiency:** The rewind re-scans the chain for *all* wallet
    addresses, not only for the imported ones.

We need a mechanism that scans for specific keys and does not disrupt the
global wallet state.

## 2. Decision

We will implement two distinct types of history recovery. The `Syncer` manages
both types, but the types have different effects on the global state.

### 2.1 Global Rewind (Manual Rescan)
*   **Trigger:** An explicit user request through `Resync(...)`.
*   **Behavior:**
    *   **Rewinds** the global `SyncedTo` watermark in the database.
    *   Sets the state to `Syncing`.
    *   Re-scans for **all** known wallet addresses.
*   **Use Case:** Recovery from a corrupted database, from a chain
    reorganization deep in history, or when a user explicitly wants to "reset"
    the wallet's view.

### 2.2 Targeted Rescan (Import Scan)
*   **Trigger:** An import of keys/accounts (e.g., `ImportPrivateKey`,
    `ImportAccount`), or a user request with specific targets.
*   **Behavior:**
    *   **Does NOT** rewind the global `SyncedTo` watermark.
    *   Sets the state to a new `Rescanning` sub-state.
    *   Constructs a **Partial Recovery State** that contains *only* the
        specific targets (addresses/scripts).
    *   Scans the requested block range for these targets.
    *   Inserts found transactions into the database.
*   **Use Case:** The addition of a new key to an existing, synced wallet.

## 3. Concurrency and Safety

We enforce strict access control based on the Orthogonal State Model. This
access control prevents race conditions during these operations.

*   **`CreateTransaction` / `FundPsbt`**: Blocked if the state is `Syncing` or
    `Rescanning`. The UTXO set is considered unstable during any scan.
*   **`Balance` / `ListUnspent`**: Allowed during `Rescanning`. These calls
    return the state of the *existing* (synced) keys. This result is safe,
    because the targeted rescan only *adds* new data. The targeted rescan does
    not invalidate existing confirmed history.

## 4. Consequences

### Pros
*   **User Experience:** The import of a key is a background task. The user
    can continue to use their existing funds immediately.
*   **Performance:** A scan for 1 key is significantly faster than a scan for
    10,000 keys (especially with CFilters).
*   **Safety:** The explicit difference between the states prevents the
    "accidental rewind" that scares users.

### Cons
*   **Complexity:** The `Syncer` logic must handle two different "modes" of
    operation (Global Loop vs. Ad-hoc Job).
*   **Database Complexity:** We must make sure that transaction inserts during
    a targeted rescan do not conflict with the global sync loop, if the two
    overlap. But the design serializes them in the `chainLoop`.
