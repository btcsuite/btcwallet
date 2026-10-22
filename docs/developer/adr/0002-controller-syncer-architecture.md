# ADR 0002: Controller-Syncer-State Architecture

## Status

- **Status:** Superseded
- **Date:** 2025-12-25

## Relationships

- **Amends:** None.
- **Supersedes:** None.
- **Amended by:** None.
- **Superseded by:**
  [ADR 0015](0015-sql-shared-chain-ownership.md), which replaces this
  lifecycle model for all maintained Managers and this synchronization model
  for SQL Managers.

## 1. Context

In the legacy `btcwallet` architecture, a single `Wallet` struct tightly
coupled three concerns: lifecycle management, synchronization logic, and state
tracking. This monolithic design caused several issues:
*   **Race Conditions:** The "Started" and "Syncing" states were ambiguous.
    Thus, it was difficult to manage concurrent access safely.
*   **Blocking Operations:** Long-running sync operations blocked
    control-plane requests (like `Stop` or `Info`).
*   **Testing Difficulty:** Because of the tight coupling, it was almost
    impossible to unit test the synchronization logic in isolation from the
    full wallet stack.

We need a robust, testable, and concurrent architecture. The architecture must
support modern features like multi-wallet management and targeted rescans.

## 2. Decision

We will adopt a **Controller-Syncer-State** pattern with an **Orthogonal State
Model**.

### 2.1 The Components

1.  **Controller (`Controller` interface / `Wallet` struct):**
    *   **Role:** The public API surface and the lifecycle manager.
    *   **Responsibility:** The Controller validates requests, manages the
        `Start/Stop` lifecycle, and delegates long-running tasks. The
        Controller never blocks on chain operations.

2.  **Syncer (`chainSyncer` interface / `syncer` struct):**
    *   **Role:** The background worker.
    *   **Responsibility:** The Syncer executes the chain loop, communicates
        with the backend, and manages the database state for synchronization.
        The Syncer is isolated and testable.

3.  **State (`walletState` struct):**
    *   **Role:** The source of truth for the wallet's status.
    *   **Responsibility:** The State keeps the wallet state in three
        independent dimensions (Lifecycle, Sync, Auth). The State uses atomic
        operations.

### 2.2 Orthogonal State Model

We do not use a single status enum. We track three separate dimensions:
*   **Lifecycle:** `Stopped` -> `Starting` -> `Started` -> `Stopping`
*   **Synchronization:** `BackendSyncing` -> `Syncing` -> `Synced` | `Rescanning`
*   **Authentication:** `Locked` | `Unlocked`

## 3. Consequences

### Pros
*   **Concurrency Safety:** State transitions are atomic and explicitly
    managed. Thus, the design eliminates race conditions.
*   **Responsiveness:** The Controller stays responsive to user requests, even
    while the Syncer does heavy I/O.
*   **Testability:** Tests can use a mock `Chain` and `Store` to test the
    `Syncer` without a full `Wallet` instance. Tests can use a mock `Syncer` to
    test the `Controller`.
*   **Clarity:** The separation of concerns makes the codebase easier to
    navigate and to reason about.

### Cons
*   **Complexity:** The design increases the number of distinct types and
    files.
*   **Indirection:** Calls to sync functionality now go through a
    channel-based request mechanism, not through direct method calls.
