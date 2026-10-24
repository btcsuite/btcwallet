# ListAddresses

List addresses and balances. The modern request selects the default BIP86
account with TaprootPubKey address type.
Wallet sources: legacy `a9ddf8d24babbe64e64446878ff93a8cc1e1d756`;
retained maintained kvdb and SQL `be0334cc543a74a954fe29c8fce8829c03f572ef`.
[Methodology](methodology.md) and [reproducibility](reproducibility.md).

### Benchmark Results

Baseline: Legacy kvdb.

🟢 below baseline · 🔴 above baseline · ⚪ baseline/equal.

#### small-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 760,296,412 | ⚪ 1.00 | 153,575,769 | ⚪ 1.00 | 3,397,077 | ⚪ 1.00 |
| Maintained kvdb | 271,787,998 | 🟢 2.80 | 4,414,717 | 🟢 34.79 | 69,797 | 🟢 48.67 |
| PostgreSQL | 9,311,998 | 🟢 81.65 | 581,080 | 🟢 264.29 | 6,749 | 🟢 503.35 |
| SQLite | 3,759,584 | 🟢 202.23 | 635,876 | 🟢 241.52 | 7,976 | 🟢 425.91 |

#### medium-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 53,701,105,341 | ⚪ 1.00 | 18,768,572,238 | ⚪ 1.00 | 680,575,820 | ⚪ 1.00 |
| Maintained kvdb | 13,463,145,777 | 🟢 3.99 | 185,518,034 | 🟢 101.17 | 3,077,915 | 🟢 221.12 |
| PostgreSQL | 30,971,692 | 🟢 1733.88 | 5,723,534 | 🟢 3279.19 | 72,335 | 🟢 9408.67 |
| SQLite | 49,672,788 | 🟢 1081.10 | 6,310,846 | 🟢 2974.02 | 84,507 | 🟢 8053.48 |

#### large-node

Single-call diagnostic: one untimed first call and one timed call per
implementation. These values are not eight-sample medians or steady-state
estimates.

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 5,845,511,598,409 | ⚪ 1.00 | 1,982,570,689,296 | ⚪ 1.00 | 73,557,224,331 | ⚪ 1.00 |
| Maintained kvdb | 1,102,993,803,294 | 🟢 5.30 | 14,371,461,800 | 🟢 137.95 | 236,295,047 | 🟢 311.29 |
| PostgreSQL | 287,983,834 | 🟢 20298.05 | 61,476,208 | 🟢 32249.40 | 730,855 | 🟢 100645.44 |
| SQLite | 2,366,466,751 | 🟢 2470.14 | 67,761,896 | 🟢 29257.90 | 852,520 | 🟢 86282.11 |

### Note

Legacy uses listAddressesDeprecated: AccountAddresses plus
TotalReceivedForAddr. It lists account-number matches across scopes and sums
lifetime receipts. The modern API selects BIP86/default and sums current
unspent balances. These native workflow ratios include different result sets
and balance semantics. Future SQL optimization should use maintained kvdb
under the modern contract and inspect pagination and balance aggregation.
