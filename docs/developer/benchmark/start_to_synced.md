# Start-to-synced

Measure one fresh native Wallet lifecycle from startup through observation of
its configured synchronized tip. Each case catches up 1,000 real Core blocks
from a saved unfunded Wallet at height 104. Populated cases have 6,000 unrelated
transactions per block; the three nonzero cases place the same 204-transaction
lnd-shaped Wallet graph into 1, 10 or 100 matching blocks.
Measured source: `f575c826401688678350fb745d5dc2621cf9e169`.
[Methodology](methodology.md#chain-synchronization),
[reproducibility](reproducibility.md#startup-full-collection) and
[shared commands](README.md#startup-to-synced).

🟢 below baseline, 🔴 above baseline, ⚪ baseline/equal.

### Benchmark Results

Baseline: legacy kvdb. Each cell is the independent median of eight unprofiled
1x runs, rounded to a whole unit; ratios use unrounded medians.

#### Coinbase-only empty blocks

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 1,394,043,397 | ⚪ 1.00 | 112,079,600 | ⚪ 1.00 | 764,017 | ⚪ 1.00 |
| Maintained kvdb | 368,440,583 | 🟢 3.78 | 33,780,948 | 🟢 3.32 | 311,755 | 🟢 2.45 |
| PostgreSQL | 491,313,396 | 🟢 2.84 | 41,618,804 | 🟢 2.69 | 364,342 | 🟢 2.10 |
| SQLite | 129,540,084 | 🟢 10.76 | 21,426,408 | 🟢 5.23 | 173,691 | 🟢 4.40 |

#### Populated blocks, 0% Wallet-hit blocks

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 94,064,879,106 | ⚪ 1.00 | 36,641,882,060 | ⚪ 1.00 | 252,858,469 | ⚪ 1.00 |
| Maintained kvdb | 112,568,844,261 | 🔴 1.20 | 33,841,833,896 | 🟢 1.08 | 141,560,556 | 🟢 1.79 |
| PostgreSQL | 96,305,740,087 | 🔴 1.02 | 33,398,029,256 | 🟢 1.10 | 138,780,646 | 🟢 1.82 |
| SQLite | 99,725,363,982 | 🔴 1.06 | 33,545,946,760 | 🟢 1.09 | 140,598,955 | 🟢 1.80 |

#### Populated blocks, 0.1% Wallet-hit blocks

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 95,040,050,627 | ⚪ 1.00 | 36,645,961,904 | ⚪ 1.00 | 252,900,535 | ⚪ 1.00 |
| Maintained kvdb | 112,291,123,448 | 🔴 1.18 | 33,950,165,832 | 🟢 1.08 | 142,345,857 | 🟢 1.78 |
| PostgreSQL | 98,548,412,087 | 🔴 1.04 | 33,494,214,312 | 🟢 1.09 | 139,698,466 | 🟢 1.81 |
| SQLite | 103,536,678,735 | 🔴 1.09 | 33,655,156,668 | 🟢 1.09 | 141,662,617 | 🟢 1.79 |

#### Populated blocks, 1% Wallet-hit blocks

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 96,500,138,357 | ⚪ 1.00 | 36,646,242,180 | ⚪ 1.00 | 252,907,441 | ⚪ 1.00 |
| Maintained kvdb | 110,707,831,342 | 🔴 1.15 | 33,900,740,200 | 🟢 1.08 | 141,900,742 | 🟢 1.78 |
| PostgreSQL | 96,098,358,335 | 🟢 1.00 | 33,481,926,956 | 🟢 1.09 | 139,523,716 | 🟢 1.81 |
| SQLite | 102,984,820,651 | 🔴 1.07 | 33,663,845,260 | 🟢 1.09 | 141,693,826 | 🟢 1.78 |

#### Populated blocks, 10% Wallet-hit blocks

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | 94,739,203,502 | ⚪ 1.00 | 36,655,256,068 | ⚪ 1.00 | 252,937,400 | ⚪ 1.00 |
| Maintained kvdb | 107,950,810,319 | 🔴 1.14 | 33,843,996,544 | 🟢 1.08 | 141,499,424 | 🟢 1.79 |
| PostgreSQL | 99,878,279,422 | 🔴 1.05 | 33,484,747,260 | 🟢 1.09 | 139,632,742 | 🟢 1.81 |
| SQLite | 103,389,093,152 | 🔴 1.09 | 33,655,196,172 | 🟢 1.09 | 141,690,218 | 🟢 1.79 |

### Notes

Legacy uses native rescan; maintained kvdb and both SQL implementations use
full-block sync. These results compare those native workflows and fixed
resources, rather than establish a general storage-backend ranking. The
maintained implementations complete the empty control faster. On populated
cases, legacy has lower median latency than maintained kvdb and SQLite;
PostgreSQL is close to legacy and slightly lower at 1%.

The populated medians do not increase monotonically with hit density. The
nonzero cases keep Wallet work fixed and change its clustering; their sample
ranges overlap. They do not establish a linear relationship. The 0% case has
no Wallet graph, and the literal empty control also removes all background
transactions. See the [collection record](reproducibility.md#startup-full-collection)
for variation, exclusions, exact targets and profile evidence.

B/op is cumulative Go allocation traffic, not peak RAM. PostgreSQL server
memory is outside these metrics. All selected full cases and separate profiles
completed with the fixed startup limits. One untimed Docker port-resolution
failure supplied no metric and was excluded; the identical retry succeeded.
One potentially contended SQLite observation was also excluded and replaced
after the other job finished; its later collection time is recorded separately.
