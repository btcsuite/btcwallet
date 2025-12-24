# ADR 0005: Explicit Rescan on Import

## 1. Context

When importing new keys, addresses, or accounts into a wallet (e.g., via `ImportPrivateKey` or `ImportAccount`), the wallet needs to scan the blockchain history to discover any existing funds associated with these new credentials.

A common pattern in some wallet implementations is to automatically trigger a rescan immediately upon import. However, this approach introduces several issues:
*   **Performance Storms:** If a user or application imports a batch of 100 keys sequentially, an automatic trigger would launch 100 overlapping, redundant rescan jobs.
*   **Blocking Behavior:** If the import method waits for the scan, a simple database insertion becomes a potentially hour-long operation.
*   **API Ambiguity:** It blurs the line between "State Management" (adding a key) and "Network Operation" (scanning the chain).

## 2. Decision

`btcwallet` will **not** automatically trigger a blockchain rescan when keys, addresses, or accounts are imported.

*   **Import Methods are Purely Database Operations:** Methods like `ImportPrivateKey`, `ImportAccount`, and `ImportScript` will only persist the data to the wallet database and return immediately.
*   **Rescans Must Be Explicit:** The caller is responsible for explicitly requesting a rescan (via `Rescan(...)`) after the import is complete.

## 3. Rationale

### 3.1 Batch Efficiency
This design allows downstream applications (like `lnd` or custom scripts) to batch imports efficiently. An application can import 1,000 keys in a loop and then trigger a **single** targeted rescan for the aggregate birthday of those keys. This is orders of magnitude more efficient than 1,000 individual scans.

### 3.2 API Clarity
Separating the concerns of "Storage" and "Synchronization" makes the API predictable.
*   `ImportXXX`: "I want to save this key." (Fast, Atomic, Synchronous)
*   `Rescan`: "I want to look for money." (Slow, Asynchronous, Cancellable)

### 3.3 User Control
The user (or calling software) retains control over system resources. They may choose to import keys now but defer the heavy scanning operation until a maintenance window or when bandwidth is available.

## 4. Consequences

### Pros
*   **Performance:** Eliminates redundant scanning during bulk imports.
*   **Responsiveness:** Import RPCs remain consistently fast.
*   **Flexibility:** Allows advanced import workflows (e.g., offline imports).

### Cons
*   **Usability Pitfall:** A naive user might import a key and be confused why their balance shows `0`. Documentation and RPC output must clearly indicate that a rescan is required to see funds.
*   **Client Burden:** Clients must implement the "Import -> Rescan" logic themselves.

## 5. Status

Accepted and Implemented.
