# ListTxns

List the complete confirmed and unmined Wallet transaction history. Query
heights 0 and -1 with no account filter.
Wallet commit:
`be0334cc543a74a954fe29c8fce8829c03f572ef`.
[Methodology](methodology.md) and [reproducibility](reproducibility.md).

### Benchmark Results

Baseline: Legacy kvdb.

🟢 below baseline · 🔴 above baseline · ⚪ baseline/equal.

#### small-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 1,575,254 | ⚪ 1.00 | 1,159,687 | ⚪ 1.00 | 26,634 | ⚪ 1.00 |
| Maintained kvdb | 700,618 | 🟢 2.25 | 790,528 | 🟢 1.47 | 13,652 | 🟢 1.95 |
| PostgreSQL | 1,943,627 | 🔴 1.23 | 1,063,292 | 🟢 1.09 | 12,248 | 🟢 2.17 |
| SQLite | 1,979,662 | 🔴 1.26 | 946,703 | 🟢 1.22 | 11,647 | 🟢 2.29 |

#### medium-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 23,022,157 | ⚪ 1.00 | 16,370,363 | ⚪ 1.00 | 519,366 | ⚪ 1.00 |
| Maintained kvdb | 10,137,296 | 🟢 2.27 | 9,558,932 | 🟢 1.71 | 256,986 | 🟢 2.02 |
| PostgreSQL | 15,134,374 | 🟢 1.52 | 11,097,406 | 🟢 1.48 | 126,840 | 🟢 4.09 |
| SQLite | 22,204,209 | 🟢 1.04 | 10,324,370 | 🟢 1.59 | 120,560 | 🟢 4.31 |

#### large-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 319,438,138 | ⚪ 1.00 | 150,146,452 | ⚪ 1.00 | 5,528,803 | ⚪ 1.00 |
| Maintained kvdb | 146,901,320 | 🟢 2.17 | 104,682,561 | 🟢 1.43 | 2,753,328 | 🟢 2.01 |
| PostgreSQL | 162,082,949 | 🟢 1.97 | 121,845,011 | 🟢 1.23 | 1,274,079 | 🟢 4.34 |
| SQLite | 511,797,153 | 🔴 1.60 | 109,733,523 | 🟢 1.37 | 1,211,269 | 🟢 4.56 |

### Note

Legacy returns transaction summaries grouped by block and a separate unmined
list, with account numbers for owned inputs and outputs. The modern API returns
a flat list of `TxDetail` values with decoded output and ownership details, but
omits those account numbers. Legacy ratios include these differences. For future
optimization, use maintained kvdb with the same history and full modern results.
Inspect SQLite's large `IN` parameter lists, row decoding and result conversion.
