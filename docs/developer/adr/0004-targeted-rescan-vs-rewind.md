# ADR 0004: Targeted Rescan vs. Global Rewind

## 1. Context

In `btcwallet`, discovering missing transactions has historically required a "Rescan." The legacy implementation treated all rescans as a "Rewind":
1.  Set the wallet's global `SyncedTo` height back to the start block.
2.  Force the wallet into a `Syncing` state.
3.  Re-process all blocks from that height forward.

This "Global Rewind" approach is problematic for modern use cases like importing a single private key or account.
*   **Disruption:** It forces the entire wallet to be "unsynced" for minutes or hours, blocking critical operations like creating transactions, even though the existing keys are perfectly up-to-date.
*   **Inefficiency:** It re-scans the chain for *all* wallet addresses, not just the imported ones.

We need a mechanism to scan for specific keys without disrupting the global wallet state.

## 2. Decision

We will implement two distinct types of history recovery, managed by the `Syncer` but differentiated by their effect on the global state.

### 2.1 Global Rewind (Manual Rescan)
*   **Trigger:** Explicit user request via `Resync(...)`.
*   **Behavior:**
    *   **Rewinds** the global `SyncedTo` watermark in the database.
    *   Sets state to `Syncing`.
    *   Re-scans for **all** known wallet addresses.
*   **Use Case:** Recovering from a corrupted database, a chain reorganization deep in history, or a user explicitly wanting to "reset" the wallet's view.

### 2.2 Targeted Rescan (Import Scan)
*   **Trigger:** Importing keys/accounts (e.g., `ImportPrivateKey`, `ImportAccount`), or a user request with specific targets.
*   **Behavior:**
    *   **Does NOT** rewind the global `SyncedTo` watermark.
    *   Sets state to a new `Rescanning` sub-state.
    *   Constructs a **Partial Recovery State** containing *only* the specific targets (addresses/scripts).
    *   Scans the requested block range for these targets.
    *   Inserts found transactions into the database.
*   **Use Case:** Adding a new key to an existing, synced wallet.

## 3. Concurrency and Safety

To prevent race conditions during these operations, we enforce strict access control based on the Orthogonal State Model.

*   **`CreateTransaction` / `FundPsbt`**: Blocked if state is `Syncing` or `Rescanning`. The UTXO set is considered unstable during any scan.
*   **`Balance` / `ListUnspent`**: Allowed during `Rescanning`. They return the state of the *existing* (synced) keys, which is safe because the targeted rescan only *adds* new data; it doesn't invalidate existing confirmed history.

## 4. Consequences

### Pros
*   **User Experience:** Importing a key is a background task. The user can continue to use their existing funds immediately.
*   **Performance:** Scanning for 1 key is significantly faster than scanning for 10,000 keys (especially with CFilters).
*   **Safety:** Explicitly differentiating the states prevents the "accidental rewind" that scares users.

### Cons
*   **Complexity:** The `Syncer` logic must handle two different "modes" of operation (Global Loop vs. Ad-hoc Job).
*   **Database Complexity:** We must ensure that inserting transactions during a targeted rescan doesn't conflict with the global sync loop if they happen to overlap (though the design serializes them in the `chainLoop`).

## 5. Status

Accepted and Implemented.
