# ADR 0003: Optimistic CFilter Batch Scanning

## 1. Context

Wallet synchronization with BIP 157/158 Compact Filters (CFilters) has a
performance problem.
*   **Latency:** Sequential fetches of filters and blocks (Header -> Filter ->
    Block) cause significant network round-trip time (RTT). The RTT is
    especially high for high-latency backends like Neutrino.
*   **The Horizon Problem:** A BIP 32 wallet must expand its "lookahead
    window" (derive new addresses) when it discovers used addresses. A block
    can contain a transaction to the last address in the window. In that case,
    the wallet must immediately derive more addresses. The wallet must also
    re-scan the subsequent blocks, so that it does not miss funds.

We need a scan algorithm that maximizes throughput (minimizes RTT) and also
guarantees correctness (respects the gap limit).

## 2. Decision

We will implement an **Optimistic Batching strategy with In-Place Resume**.

### 2.1 The Strategy

1.  **Optimistic Fetch:** The wallet fetches headers, CFilters, and (if
    matched) blocks for a large batch (e.g., 100 blocks) in parallel. The
    fetch assumes that the current address lookahead window is sufficient.
2.  **Sequential Process:** The wallet processes the downloaded blocks
    sequentially in memory.
3.  **In-Place Resume:** When the wallet processes Block `N`, the wallet can
    trigger a horizon expansion (new addresses derived). If an expansion occurs:
    *   The process loop pauses.
    *   The wallet updates its internal watchlist with the new addresses.
    *   The wallet **re-scans** the remaining blocks in the *current batch*
        (Blocks `N+1` to `End`) with the updated watchlist.
    *   If necessary, the wallet fetches missing blocks that now match the new
        filters.

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
*   **High Throughput:** In the common case (no sequential expansion), the
    wallet fetches data in large, efficient batches. These batches saturate
    the network connection.
*   **Correctness:** A user can receive a chain of payments to sequential
    addresses in a single batch. The "In-Place Resume" logic guarantees that
    the wallet discovers all of these payments.
*   **Efficiency:** The design avoids the naive "Stop-and-Go" approach, which
    processes one block at a time. That approach is prohibitively slow.

### Cons
*   **Complexity:** The resume logic adds complexity to the implementation of
    the scan loop.
*   **Redundant Work (Edge Case):** In the worst case (sequential expansion in
    every block), the algorithm degrades to repeated re-matches of filters.
    However, this case is rare in practice.

## 4. Status

Accepted and Implemented.
