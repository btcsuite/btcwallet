# ADR 0002: Controller-Syncer-State Architecture

## 1. Context

The legacy `btcwallet` architecture tightly coupled lifecycle management, synchronization logic, and state tracking within a single `Wallet` struct. This monolithic design led to several issues:
*   **Race Conditions:** Ambiguity between "Started" and "Syncing" states made it difficult to safely manage concurrent access.
*   **Blocking Operations:** Long-running sync operations would block control-plane requests (like `Stop` or `Info`).
*   **Testing Difficulty:** The tight coupling made it nearly impossible to unit test synchronization logic in isolation from the full wallet stack.

We need a robust, testable, and concurrent architecture to support modern features like multi-wallet management and targeted rescans.

## 2. Decision

We will adopt a **Controller-Syncer-State** pattern with an **Orthogonal State Model**.

### 2.1 The Components

1.  **Controller (`Controller` interface / `Wallet` struct):**
    *   **Role:** The public API surface and lifecycle manager.
    *   **Responsibility:** Validates requests, manages the `Start/Stop` lifecycle, and delegates long-running tasks. It never blocks on chain operations.

2.  **Syncer (`chainSyncer` interface / `syncer` struct):**
    *   **Role:** The background worker.
    *   **Responsibility:** Executes the chain loop, communicates with the backend, and manages the database state for synchronization. It is isolated and testable.

3.  **State (`walletState` struct):**
    *   **Role:** The source of truth for the wallet's status.
    *   **Responsibility:** Maintains state across three independent dimensions (Lifecycle, Sync, Auth) using atomic operations.

### 2.2 Orthogonal State Model

Instead of a single status enum, we track three separate dimensions:
*   **Lifecycle:** `Stopped` -> `Starting` -> `Started` -> `Stopping`
*   **Synchronization:** `BackendSyncing` -> `Syncing` -> `Synced` | `Rescanning`
*   **Authentication:** `Locked` | `Unlocked`

## 3. Consequences

### Pros
*   **Concurrency Safety:** State transitions are atomic and explicitly managed, eliminating race conditions.
*   **Responsiveness:** The Controller remains responsive to user requests even while the Syncer is performing heavy I/O.
*   **Testability:** The `Syncer` can be tested with a mock `Chain` and `Store` without instantiating a full `Wallet`. The `Controller` can be tested with a mock `Syncer`.
*   **Clarity:** The separation of concerns makes the codebase easier to navigate and reason about.

### Cons
*   **Complexity:** Increases the number of distinct types and files.
*   **Indirection:** Calls to sync functionality now go through a channel-based request mechanism rather than direct method calls.

## 4. Status

Accepted and Implemented.
