# ADR 0003: Optimistic CFilter Batch Scanning

## 1. Context

Synchronizing a wallet using BIP 157/158 Compact Filters (CFilters) presents a performance challenge.
*   **Latency:** Fetching filters and blocks sequentially (Header -> Filter -> Block) incurs significant network round-trip time (RTT), especially for high-latency backends like Neutrino.
*   **The Horizon Problem:** BIP 32 wallets must expand their "lookahead window" (derive new addresses) when used addresses are discovered. If a block contains a transaction to the last address in the window, the wallet must immediately derive more addresses and re-scan subsequent blocks to ensure no funds are missed.

We need a scanning algorithm that maximizes throughput (minimizing RTT) while guaranteeing correctness (respecting the gap limit).

## 2. Decision

We will implement an **Optimistic Batching strategy with In-Place Resume**.

### 2.1 The Strategy

1.  **Optimistic Fetch:** The wallet fetches headers, CFilters, and (if matched) blocks for a large batch (e.g., 100 blocks) in parallel, assuming the current address lookahead window is sufficient.
2.  **Sequential Process:** The downloaded blocks are processed sequentially in memory.
3.  **In-Place Resume:** If processing Block `N` triggers a horizon expansion (new addresses derived):
    *   The processing loop pauses.
    *   The wallet updates its internal watchlist with the new addresses.
    *   The wallet **re-scans** the remaining blocks in the *current batch* (Blocks `N+1` to `End`) using the updated watchlist.
    *   If necessary, it fetches missing blocks that now match the new filters.

### 2.2 Logic Flow

```
Batch Loop:
  1. Fetch Filters for Batch [Start, End]
  2. Match Filters against Current Watchlist
  3. Fetch Matched Blocks
  4. Block Loop (i from Start to End):
       a. Process Block(i)
       b. If Horizon Expanded:
            i. Update Watchlist
            ii. Re-Match Filters for [i+1, End]
            iii. Fetch Newly Matched Blocks
            iv. Continue Loop
```

## 3. Consequences

### Pros
*   **High Throughput:** In the common case (no sequential expansion), the wallet fetches data in large, efficient batches, saturating the network connection.
*   **Correctness:** The "In-Place Resume" logic guarantees that even if a user receives a chain of payments to sequential addresses in a single batch, the wallet will discover all of them.
*   **Efficiency:** It avoids the naive "Stop-and-Go" approach of processing one block at a time, which is prohibitively slow.

### Cons
*   **Complexity:** The resumption logic adds complexity to the scan loop implementation.
*   **Redundant Work (Edge Case):** In the worst-case scenario (sequential expansion in every block), the algorithm degrades to re-matching filters repeatedly. However, this is rare in practice.

## 4. Status

Accepted and Implemented.
