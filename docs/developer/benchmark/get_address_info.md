# GetAddressInfo

Read metadata for the P2TR address of the cooperative return selected by
GetUtxo.
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
| Legacy kvdb | 2,135 | ⚪ 1.00 | 1,544 | ⚪ 1.00 | 36 | ⚪ 1.00 |
| Maintained kvdb | 267,246,064 | 🔴 125173.80 | 3,360,087 | 🔴 2176.22 | 49,379 | 🔴 1371.62 |
| PostgreSQL | 173,258 | 🔴 81.15 | 5,367 | 🔴 3.48 | 90 | 🔴 2.50 |
| SQLite | 94,238 | 🔴 44.14 | 4,455 | 🔴 2.89 | 94 | 🔴 2.61 |

##### medium-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 2,545 | ⚪ 1.00 | 2,392 | ⚪ 1.00 | 55 | ⚪ 1.00 |
| Maintained kvdb | 2,693,303,981 | 🔴 1058480.64 | 34,372,472 | 🔴 14369.76 | 547,104 | 🔴 9947.35 |
| PostgreSQL | 173,760 | 🔴 68.29 | 5,383 | 🔴 2.25 | 92 | 🔴 1.67 |
| SQLite | 101,995 | 🔴 40.08 | 4,472 | 🔴 1.87 | 96 | 🔴 1.75 |

##### large-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 3,338 | ⚪ 1.00 | 1,742 | ⚪ 1.00 | 60 | ⚪ 1.00 |
| Maintained kvdb | 26,986,268,463 | 🔴 8085773.32 | 347,322,470 | 🔴 199381.44 | 5,671,625 | 🔴 95321.43 |
| PostgreSQL | 653,109 | 🔴 195.69 | 5,384 | 🔴 3.09 | 93 | 🔴 1.56 |
| SQLite | 121,300 | 🔴 36.34 | 4,456 | 🔴 2.56 | 96 | 🔴 1.61 |

#### Different existing items (pending)

Read different P2TR addresses of existing cooperative returns once each.

#### Not found (pending)

Read a different valid P2TR address absent from the wallet on each call.

### Note

Legacy returns a managed-address object without reading all its metadata methods
in the benchmark. The modern API builds an `AddressInfo` value with address
type, public key and available derivation metadata. The legacy ratios include
this difference in work. Future SQL optimization should retain the modern
snapshot and use maintained kvdb as the reference. Inspect point query cost and
metadata mapping.
