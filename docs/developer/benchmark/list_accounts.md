# ListAccounts

List Wallet accounts with their normal balance reads. The modern request
returns all regular scoped accounts.
Wallet sources: legacy `a9ddf8d24babbe64e64446878ff93a8cc1e1d756`;
retained maintained kvdb and SQL `be0334cc543a74a954fe29c8fce8829c03f572ef`.
[Methodology](methodology.md) and [reproducibility](reproducibility.md).

### Benchmark Results

Baseline: Legacy kvdb.

🟢 below baseline · 🔴 above baseline · ⚪ baseline/equal.

#### small-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 2,540,979 | ⚪ 1.00 | 2,139,508 | ⚪ 1.00 | 39,372 | ⚪ 1.00 |
| Maintained kvdb | 876,646 | 🟢 2.90 | 875,421 | 🟢 2.44 | 11,992 | 🟢 3.28 |
| PostgreSQL | 890,159 | 🟢 2.85 | 490,596 | 🟢 4.36 | 5,883 | 🟢 6.69 |
| SQLite | 1,900,063 | 🟢 1.34 | 497,400 | 🟢 4.30 | 5,844 | 🟢 6.74 |

#### medium-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 28,309,768 | ⚪ 1.00 | 24,207,227 | ⚪ 1.00 | 677,636 | ⚪ 1.00 |
| Maintained kvdb | 6,010,021 | 🟢 4.71 | 5,333,016 | 🟢 4.54 | 142,137 | 🟢 4.77 |
| PostgreSQL | 2,004,946 | 🟢 14.12 | 490,712 | 🟢 49.33 | 5,891 | 🟢 115.03 |
| SQLite | 5,776,391 | 🟢 4.90 | 497,072 | 🟢 48.70 | 5,851 | 🟢 115.82 |

#### large-node

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 357,905,621 | ⚪ 1.00 | 233,387,843 | ⚪ 1.00 | 7,566,212 | ⚪ 1.00 |
| Maintained kvdb | 70,141,480 | 🟢 5.10 | 47,460,949 | 🟢 4.92 | 1,528,875 | 🟢 4.95 |
| PostgreSQL | 12,915,960 | 🟢 27.71 | 491,080 | 🟢 475.25 | 5,892 | 🟢 1284.15 |
| SQLite | 48,811,577 | 🟢 7.33 | 499,024 | 🟢 467.69 | 5,853 | 🟢 1292.71 |

### Note

Both kvdb implementations reuse waddrmgr's cache for regular account keys
and metadata. Each call still reads unspent outputs and calculates balances.
These results include warm native caches from repeated reads.

Legacy uses listAccountsDeprecated: Accounts across active scopes. It includes
imported aliases and assigns balances by account number across scopes. The
modern API lists regular scoped accounts. SQL stores the internal-key
exclusion from chain sync; kvdb cannot store that policy. These native
workflow ratios include those result differences. Future SQL optimization
should use maintained kvdb and inspect balance aggregation and result mapping.
