# GetUtxo

Read one retained cooperative-close output. Select the lowest transaction
hash, then output index, among cooperative returns of 398,070 sat.
Measured sources for repeated-item results:
legacy `a9ddf8d24babbe64e64446878ff93a8cc1e1d756`;
retained maintained kvdb and SQL `be0334cc543a74a954fe29c8fce8829c03f572ef`.
[Methodology](methodology.md) and [reproducibility](reproducibility.md).

### Benchmark Results

Baseline: Legacy kvdb.

🟢 below baseline · 🔴 above baseline · ⚪ baseline/equal.

The different-item and not-found tables are pending a completed matched
collection.

#### Repeated existing item

##### small-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 8,518 | ⚪ 1.00 | 6,402 | ⚪ 1.00 | 155 | ⚪ 1.00 |
| Maintained kvdb | 172,230 | 🔴 20.22 | 213,265 | 🔴 33.31 | 3,190 | 🔴 20.58 |
| PostgreSQL | 309,456 | 🔴 36.33 | 7,957 | 🔴 1.24 | 152 | 🟢 1.02 |
| SQLite | 139,175 | 🔴 16.34 | 6,974 | 🔴 1.09 | 168 | 🔴 1.08 |

##### medium-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 11,247 | ⚪ 1.00 | 8,946 | ⚪ 1.00 | 284 | ⚪ 1.00 |
| Maintained kvdb | 2,250,294 | 🔴 200.08 | 2,356,120 | 🔴 263.39 | 61,257 | 🔴 216.07 |
| PostgreSQL | 284,444 | 🔴 25.29 | 7,972 | 🟢 1.12 | 154 | 🟢 1.84 |
| SQLite | 155,890 | 🔴 13.86 | 6,969 | 🟢 1.28 | 170 | 🟢 1.67 |

##### large-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 13,059 | ⚪ 1.00 | 7,849 | ⚪ 1.00 | 303 | ⚪ 1.00 |
| Maintained kvdb | 32,105,953 | 🔴 2458.53 | 28,305,622 | 🔴 3606.50 | 721,284 | 🔴 2380.48 |
| PostgreSQL | 297,760 | 🔴 22.80 | 7,981 | 🔴 1.02 | 155 | 🟢 1.95 |
| SQLite | 160,676 | 🔴 12.30 | 6,986 | 🟢 1.12 | 171 | 🟢 1.77 |

#### Different existing items (pending)

Read different cooperative-close outpoints once each.

#### Not found (pending)

Read a different outpoint from a transaction absent from the wallet on each
call.

### Note

Legacy uses getUtxoDeprecated: FetchOutpointInfo, ownership metadata and lock
lookup. Its fixed local chain tip excludes RPC transport and per-call mock
recording. Its confirmed count omits the confirming block. These native
workflow ratios include different confirmation semantics. Future SQL
optimization should use maintained kvdb under the modern contract and inspect
point queries and repeated Wallet metadata reads.
