# ListUnspent

List all unspent outputs across all accounts with confirmations 0..2147483647.
Wallet commit: `be0334cc543a74a954fe29c8fce8829c03f572ef`.
[Methodology](methodology.md) and [reproducibility](reproducibility.md).

### Benchmark Results

Baseline: Legacy kvdb.

🟢 below baseline · 🔴 above baseline · ⚪ baseline/equal.

#### small-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 907,965 | ⚪ 1.00 | 474,162 | ⚪ 1.00 | 9,589 | ⚪ 1.00 |
| Maintained kvdb | 623,397 | 🟢 1.46 | 581,598 | 🔴 1.23 | 11,196 | 🔴 1.17 |
| PostgreSQL | 6,169,258 | 🔴 6.79 | 177,564 | 🟢 2.67 | 1,773 | 🟢 5.41 |
| SQLite | 854,716 | 🟢 1.06 | 207,435 | 🟢 2.29 | 2,191 | 🟢 4.38 |

#### medium-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 10,644,085 | ⚪ 1.00 | 5,992,844 | ⚪ 1.00 | 166,307 | ⚪ 1.00 |
| Maintained kvdb | 8,106,385 | 🟢 1.31 | 7,783,124 | 🔴 1.30 | 189,089 | 🔴 1.14 |
| PostgreSQL | 5,853,691 | 🟢 1.82 | 1,848,111 | 🟢 3.24 | 18,244 | 🟢 9.12 |
| SQLite | 5,759,285 | 🟢 1.85 | 2,160,896 | 🟢 2.77 | 22,298 | 🟢 7.46 |

#### large-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 126,363,496 | ⚪ 1.00 | 58,812,389 | ⚪ 1.00 | 1,825,882 | ⚪ 1.00 |
| Maintained kvdb | 101,414,476 | 🟢 1.25 | 72,161,406 | 🔴 1.23 | 2,062,009 | 🔴 1.13 |
| PostgreSQL | 57,567,241 | 🟢 2.20 | 22,209,699 | 🟢 2.65 | 181,907 | 🟢 10.04 |
| SQLite | 61,611,780 | 🟢 2.05 | 25,654,775 | 🟢 2.29 | 222,322 | 🟢 8.21 |

### Note

Legacy returns text hashes/scripts and BTC amounts, orders by transaction age
and marks Taproot outputs unspendable. Modern returns typed values and
satoshis, orders by amount and derives spendability from Wallet/custody state.
The [original
review](https://github.com/btcsuite/btcwallet/pull/1059#discussion_r2418971797)
explains why spendability correctness can require more work. Current Store
rows supply that metadata; the historical AddressDetails call pattern does not
describe the current implementation. These ratios compare native API costs.
For future optimization, compare SQL with maintained kvdb under the same
modern result contract. Inspect query plans and round trips first, then row
decoding as results grow.
