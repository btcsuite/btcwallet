# Synchronization Modes: Compact Filters vs. Full Blocks

When connecting to a chain backend, `btcwallet` offers two distinct synchronization strategies, configured via the `SyncMethod` parameter:

1.  **`SyncMethodCFilters`**: Uses lightweight Compact Filters (Neutrino) to scan for relevant transactions.
2.  **`SyncMethodFullBlocks`**: Downloads full blocks (or batches of blocks) to scan locally.

Choosing the right mode can significantly impact your wallet's startup time, bandwidth usage, and CPU load. This guide explains the differences and provides performance benchmarks to help you decide which mode fits your use case.

## Summary Recommendation

| Transaction Density | Recommended Mode | Why? |
| :--- | :--- | :--- |
| **Low Frequency** (< 1 hit per 100 blocks) | **`SyncMethodCFilters`** | **~4x Faster.** Optimized for sparse histories by avoiding block data entirely. |
| **Moderate Frequency** (1 hit per 10-100 blocks) | **`SyncMethodCFilters`** | **~2x Faster.** Still faster than full blocks due to reduced data transfer. |
| **High Frequency** (> 1 hit per 10 blocks) | **`SyncMethodFullBlocks`** | **High Throughput.** Most efficient when hits are dense, avoiding matching overhead. |

---

## 1. Compact Filters (CFilter)
**Default & Recommended for 99% of Users.**

In this mode (`SyncMethodCFilters`), the wallet downloads lightweight **Neutrino Compact Filters** (Golomb-Rice filters) for each block to check if the block contains any relevant transactions.
*   **Process**: Fetch Filter -> Match Filter -> (Only if Match) Fetch Block.
*   **Pros**: 
    *   Extremely fast for "empty" blocks.
    *   Minimal bandwidth usage (filters are ~15KB vs blocks ~1-4MB).
*   **Cons**: 
    *   Slower if every block is a "hit" (requires double round-trips: get filter, then get block).

## 2. Full Blocks
**Recommended for High-Density Wallets.**

In this mode (`SyncMethodFullBlocks`), the wallet indiscriminately downloads every full block (or batches of blocks) and scans them locally.
*   **Process**: Fetch Batch of Blocks -> Scan All.
*   **Pros**: 
    *   Linear scaling for high-traffic wallets.
    *   Eliminates the "Match Filter -> Fetch Block" latency penalty when hits are frequent.
*   **Cons**: 
    *   High bandwidth (downloads the entire blockchain history during rescan).
    *   High CPU/Memory usage (parsing gigabytes of JSON/Hex block data).

---

## Performance Analysis & UTXO Density

We benchmarked both modes against a standard `bitcoind` node over a range of 1,000 blocks. The performance depends heavily on **UTXO Density**: how often your wallet sends or receives a transaction relative to the number of blocks.

### Benchmark Results (1,000 Blocks)

| Wallet Activity (Density) | Real-World Equivalent | `SyncMethodFullBlocks` | `SyncMethodCFilters` | Winner |
| :--- | :--- | :--- | :--- | :--- |
| **0.001 (0.1%)** | **1 Tx / Week** | ~1.9x Faster | **~3.8x Faster** | **`SyncMethodCFilters`** |
| **0.01 (1.0%)** | **1 Tx / 16 Hours** | ~1.5x Faster | **~2.1x Faster** | **`SyncMethodCFilters`** |
| **0.1 (10%)** | **10 Txs / Hour** | **~1.8x Faster** | Slower | **`SyncMethodFullBlocks`** |

* *Speedups are compared against the legacy synchronization API.*

### Interpreting Density
*   **Low to Moderate Frequency (Density < 0.1)**: This represents the vast majority of wallet usage. If your wallet receives or sends funds a few times a day or less, your transaction history is "sparse" relative to the blockchain (~144 blocks/day). **Use `SyncMethodCFilters`** to save bandwidth and reduce sync time.
*   **High Frequency (Density > 0.1)**: This represents "dense" wallets that are active in **1 out of every 10 blocks** (or more). For these high-traffic scenarios, the overhead of double-fetching (filter match then block fetch) exceeds the cost of just fetching everything. **Use `SyncMethodFullBlocks`** for maximum throughput.

## Conclusion

The new synchronization architecture in `btcwallet` is designed to be adaptive. By default, **`SyncMethodCFilters`** provides a superior experience for typical users, offering massive speedups and bandwidth savings. However, for high-workload scenarios where the wallet effectively indexes a significant portion of the chain, **`SyncMethodFullBlocks`** mode provides a robust, high-throughput alternative that outperforms the legacy implementation.
