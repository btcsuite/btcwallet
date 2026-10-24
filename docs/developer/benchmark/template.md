# <Method>

<Describe the completed API call and its timing boundary in one sentence.>
Wallet commit: `<full measured SHA>`.
[Methodology](methodology.md), [reproducibility](reproducibility.md) and
[shared commands](README.md).

### Benchmark Results

#### <Dataset name>

| Implementation | ns/op | Ratio | B/op | Ratio | allocs/op | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Legacy kvdb | ... | ⚪ 1.00 | ... | ⚪ 1.00 | ... | ⚪ 1.00 |
| Maintained kvdb | ... | ... | ... | ... | ... | ... |
| PostgreSQL | ... | ... | ... | ... | ... | ... |
| SQLite | ... | ... | ... | ... | ... | ... |

<Use a separate table per dataset. Describe the sample count, target duration,
untimed first call, iteration policy and summary statistic. Show whole-number
metrics with thousands separators. Ratios use exact medians before rounding
and show two decimals: 🟢 lower, 🔴 higher, ⚪ equal or baseline. Use faster/slower
for time and lower/higher for allocations. Add no multiplier sign. For lower
values, divide baseline by measured value; for higher values, use the
reciprocal.
State the common measured SHA once above the tables. Give a short
interpretation and exclude smoke results. State the run label/date and native
serial orders. If legacy does not match the request, show unavailable without
metrics and declare maintained kvdb as the ratio baseline.>

### Data

<Identify the shared dataset and link to its definition in reproducibility.md.
Describe only the method's request, state and changes to its private copy.
Keep rationale in methodology.md and exact data/setup in reproducibility.md.>

| Parameter | Value |
| --- | --- |
| Shared dataset | ... |
| Method-specific changes | ... |
| Wallet state | ... |
| Request | ... |
