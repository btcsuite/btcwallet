# GetTx

Read the cooperative-close transaction selected by GetUtxo; it has one input
and two outputs.
Measured source for repeated-item results:
`be0334cc543a74a954fe29c8fce8829c03f572ef`.
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
| Legacy kvdb | 5,251 | ⚪ 1.00 | 4,097 | ⚪ 1.00 | 94 | ⚪ 1.00 |
| Maintained kvdb | 6,985 | 🔴 1.33 | 4,128 | 🔴 1.01 | 82 | 🟢 1.15 |
| PostgreSQL | 543,288 | 🔴 103.46 | 14,301 | 🔴 3.49 | 312 | 🔴 3.32 |
| SQLite | 144,215 | 🔴 27.46 | 11,323 | 🔴 2.76 | 252 | 🔴 2.68 |

##### medium-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 6,921 | ⚪ 1.00 | 5,617 | ⚪ 1.00 | 183 | ⚪ 1.00 |
| Maintained kvdb | 9,117 | 🔴 1.32 | 4,832 | 🟢 1.16 | 155 | 🟢 1.18 |
| PostgreSQL | 867,271 | 🔴 125.32 | 14,324 | 🔴 2.55 | 313 | 🔴 1.71 |
| SQLite | 159,105 | 🔴 22.99 | 11,316 | 🔴 2.01 | 253 | 🔴 1.38 |

##### large-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 8,312 | ⚪ 1.00 | 5,129 | ⚪ 1.00 | 198 | ⚪ 1.00 |
| Maintained kvdb | 10,647 | 🔴 1.28 | 5,072 | 🟢 1.01 | 169 | 🟢 1.17 |
| PostgreSQL | 895,652 | 🔴 107.75 | 14,354 | 🔴 2.80 | 317 | 🔴 1.60 |
| SQLite | 162,125 | 🔴 19.50 | 11,356 | 🔴 2.21 | 257 | 🔴 1.30 |

#### Different existing items (pending)

Read different cooperative-close transaction hashes once each.

#### Not found (pending)

Read a different transaction hash absent from the wallet on each call.

### Note

Legacy returns a transaction summary with raw data and account numbers for owned
inputs and outputs. The modern API returns decoded `TxDetail` values with output
details, previous-outpoint ownership, value, weight, fee rate and status, but
omits those account numbers. Legacy ratios include these differences. Future
work should preserve the modern payload and compare with maintained kvdb.
Investigate SQLite statement preparation and PostgreSQL metadata and ownership
query round trips.
